'use strict';

// themeguard.js —— did-change-theme-color（<meta name="theme-color">）收口内核。
//
// 威胁模型：
//   页面可用 <meta name="theme-color"> 驱动 Electron 窗口标题栏/工具栏配色。
//   1) 仿冒钓鱼：把顶栏颜色调成与伪造的“银行/登录页”UI 一致，弱化真实浏览器
//      边框与内容页的分界，让用户分不清地址栏属于谁（clickjacking / UI 红区伪装）；
//   2) 闪烁干扰：JS 在 requestAnimationFrame 里高频切换 meta 颜色，制造闪烁诱导
//      点击或诱发光敏反应，同时打爆到窗口层的主题 IPC；
//   3) 脏输入：颜色字符串可能携带控制字符/超长内容，进入日志或配色解析器时出问题。
//   本内核只做“白名单颜色 + 频率收敛”，真正的 UI 红区（地址栏/证书/下载条）永远
//   不被页面主题色覆盖。纯函数，无 DOM/Electron 依赖。

const THEME_ACCEPT = 'accept';
const THEME_HOLD = 'hold';
const THEME_DROP = 'drop';

const HOLD_NO_CHANGE = 'theme-no-change';
const HOLD_TOO_SOON = 'theme-too-soon';
const DROP_BAD_COLOR = 'theme-bad-color';
const DROP_FLOOD = 'theme-flood-exceeded';
const DROP_COOLDOWN = 'theme-cooldown-active';

const THEME_MAX_COLOR_CHARS = 64;
const THEME_MIN_INTERVAL_MS = 200;
const THEME_BURST_WINDOW_MS = 1_000;
const THEME_BURST_LIMIT = 8;
const THEME_LONG_WINDOW_MS = 10_000;
const THEME_LONG_LIMIT = 60;
const THEME_COOLDOWN_MS = 3_000;

// 只接受浏览器 UI 渲染所需的最小颜色集合：
// #rgb / #rgba / #rrggbb / #rrggbbaa，rgb()/rgba() 数字分量 0-255、alpha 0-1。
// 拒绝 hsl/颜色关键字/color()/calc() 等，避免把任意 CSS 表达式送进配色解析。
const HEX_COLOR_RE = /^#(?:[0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/;
const RGB_FUNC_RE = /^rgba?\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*(?:,\s*(\d?(?:\.\d+)?|1(?:\.0+)?)\s*)?\)$/;

const C0_CONTROL_RE = /[\x00-\x1f\x7f]/g;

// normalizeThemeColor 返回 { ok, color, changed }。入参为空串表示页面移除 meta，
// 视为“恢复默认”，是合法清空信号；changed 由调用方结合 lastColor 判断。
function normalizeThemeColor(input) {
  if (typeof input !== 'string') return { ok: false, color: '', empty: false };
  const color = input.replace(C0_CONTROL_RE, '').trim().toLowerCase();
  if (color.length === 0) return { ok: true, color: '', empty: true };
  if (color.length > THEME_MAX_COLOR_CHARS) return { ok: false, color: '', empty: false };

  if (HEX_COLOR_RE.test(color)) return { ok: true, color, empty: false };

  const m = RGB_FUNC_RE.exec(color);
  if (m) {
    const r = Number(m[1]);
    const g = Number(m[2]);
    const b = Number(m[3]);
    if (r > 255 || g > 255 || b > 255) return { ok: false, color: '', empty: false };
    if (m[4] !== undefined) {
      const a = Number(m[4]);
      if (!Number.isFinite(a) || a < 0 || a > 1) return { ok: false, color: '', empty: false };
    }
    return { ok: true, color, empty: false };
  }
  return { ok: false, color: '', empty: false };
}

function pruneOlderThan(list, cutoff) {
  let i = 0;
  while (i < list.length && list[i] < cutoff) i++;
  if (i > 0) list.splice(0, i);
}

function countSince(sortedTimes, cutoff) {
  let n = 0;
  for (let i = sortedTimes.length - 1; i >= 0; i--) {
    if (sortedTimes[i] >= cutoff) n++;
    else break;
  }
  return n;
}

function createThemeState(now) {
  return {
    times: [],
    accepted: 0,
    held: 0,
    dropped: 0,
    lastAppliedAt: 0,
    lastColor: null,
    cooldownUntil: 0,
    createdAt: now || 0,
  };
}

function resetForNavigation(state) {
  if (!state) return;
  state.times = [];
  state.lastAppliedAt = 0;
  state.lastColor = null;
  state.cooldownUntil = 0;
}

// decideThemeColor 裁决一次 did-change-theme-color。空串（移除 meta）在冷却期也
// 放行，保证页面离开后顶栏不会被上一个恶意配色粘住。
function decideThemeColor(state, rawColor, now) {
  if (!state) throw new TypeError('themeguard: state required');
  const parsed = normalizeThemeColor(rawColor);
  const baseCounts = () => ({
    burstCount: countSince(state.times, now - THEME_BURST_WINDOW_MS),
    longCount: state.times.length, droppedTotal: state.dropped,
  });

  if (!parsed.ok) {
    state.dropped += 1;
    return { action: THEME_DROP, reason: DROP_BAD_COLOR, color: '', ...baseCounts() };
  }

  const inCooldownBefore = state.cooldownUntil > now;
  state.times.push(now);
  pruneOlderThan(state.times, now - THEME_LONG_WINDOW_MS);
  const burst = countSince(state.times, now - THEME_BURST_WINDOW_MS);
  let flood = null;
  if (burst > THEME_BURST_LIMIT || state.times.length > THEME_LONG_LIMIT) {
    state.cooldownUntil = now + THEME_COOLDOWN_MS;
    flood = { reason: DROP_FLOOD, burstCount: burst, longCount: state.times.length };
  }

  // 清空信号即便在冷却/越限时也送达（恢复默认顶栏），但仍计入频率。
  if (parsed.empty) {
    if (state.lastColor === '' && state.lastAppliedAt !== 0) {
      state.held += 1;
      return { action: THEME_HOLD, reason: HOLD_NO_CHANGE, color: '', ...baseCounts() };
    }
    state.lastColor = '';
    state.lastAppliedAt = now;
    state.accepted += 1;
    return { action: THEME_ACCEPT, reason: '', color: '', ...baseCounts() };
  }

  if (state.cooldownUntil > now || flood) {
    state.dropped += 1;
    return {
      action: THEME_DROP,
      reason: inCooldownBefore ? DROP_COOLDOWN : (flood ? flood.reason : DROP_COOLDOWN),
      color: parsed.color,
      burstCount: flood ? flood.burstCount : burst,
      longCount: flood ? flood.longCount : state.times.length,
      cooldownUntil: state.cooldownUntil, droppedTotal: state.dropped,
    };
  }

  if (state.cooldownUntil > 0 && state.cooldownUntil <= now) state.cooldownUntil = 0;
  if (parsed.color === state.lastColor) {
    state.held += 1;
    return { action: THEME_HOLD, reason: HOLD_NO_CHANGE, color: parsed.color, ...baseCounts() };
  }
  if (now - state.lastAppliedAt < THEME_MIN_INTERVAL_MS && state.lastAppliedAt !== 0) {
    state.held += 1;
    return { action: THEME_HOLD, reason: HOLD_TOO_SOON, color: parsed.color, ...baseCounts() };
  }

  state.accepted += 1;
  state.lastColor = parsed.color;
  state.lastAppliedAt = now;
  return { action: THEME_ACCEPT, reason: '', color: parsed.color, ...baseCounts() };
}

function describeThemeReason(reason) {
  switch (reason) {
    case HOLD_NO_CHANGE:
      return '页面主题色未变化，已合并';
    case HOLD_TOO_SOON:
      return '页面主题色变化过快，已合并';
    case DROP_BAD_COLOR:
      return '页面请求的主题色不在允许的颜色格式内，已忽略';
    case DROP_FLOOD:
      return '页面异常频繁切换主题色（疑似闪烁干扰/伪装），冷却期内锁定顶栏配色';
    case DROP_COOLDOWN:
      return '主题色闪烁冷却期内的变更已忽略';
    default:
      return '页面主题色';
  }
}

module.exports = {
  THEME_ACCEPT,
  THEME_HOLD,
  THEME_DROP,
  HOLD_NO_CHANGE,
  HOLD_TOO_SOON,
  DROP_BAD_COLOR,
  DROP_FLOOD,
  DROP_COOLDOWN,
  THEME_MAX_COLOR_CHARS,
  THEME_MIN_INTERVAL_MS,
  THEME_BURST_WINDOW_MS,
  THEME_BURST_LIMIT,
  THEME_LONG_WINDOW_MS,
  THEME_LONG_LIMIT,
  THEME_COOLDOWN_MS,
  normalizeThemeColor,
  createThemeState,
  resetForNavigation,
  decideThemeColor,
  describeThemeReason,
};
