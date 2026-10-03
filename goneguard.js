'use strict';

// goneguard.js —— 渲染进程 / GPU 进程崩溃与页面无响应的处置策略（纯判定内核）。
//
// 威胁与稳定性模型：
//   1) 渲染进程崩溃（render-process-gone）或 GPU 进程崩溃（child-process-gone）后，
//      标签会变成白屏 / 死页。直接无限 reload 会和“一打开就崩”的页面形成崩溃循环，
//      占满 CPU、反复打远端接口，甚至被利用成放大请求的手段。必须有界定速 + 熔断。
//   2) 页面无响应（unresponsive）时，盲目 reload 会打断用户正在填写的内容；需要
//      冷却窗口，窗口内的重复无响应事件只计一次，交给界面提示“等待 / 重载”。
//   3) 崩溃后重载必须回到安全起点：只重载 http(s)/file/内部页，绝不重载导致崩溃的
//      data:/blob: 瞬时上下文（那种内容由脚本即时生成，重载无意义且可能复现攻击），
//      外部协议更不能在崩溃恢复时被再次唤起。
//
// 本模块不依赖 Electron：输入当前时间与 URL，输出决策。真实 reload / 错误页由
// main.js 执行。

const RELOADABLE_SCHEMES = new Set(['http:', 'https:', 'file:', 'cosy:']);
// 默认策略常量（可被 options 覆盖）。
const DEFAULT_WINDOW_MS = 60000;       // 计数窗口
const DEFAULT_MAX_AUTO_RELOADS = 2;    // 窗口内自动重载上限
const DEFAULT_RELOAD_COOLDOWN_MS = 3000; // 两次自动重载最小间隔
const DEFAULT_UNRESPONSIVE_COOLDOWN_MS = 8000; // 无响应提示冷却

function parseUrl(raw) {
  if (typeof raw !== 'string' || raw === '') return null;
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

// isReloadable 判断崩溃后是否允许自动重载该 URL。
function isReloadable(rawUrl) {
  const u = parseUrl(rawUrl);
  if (!u) return false;
  return RELOADABLE_SCHEMES.has(u.protocol.toLowerCase());
}

// createState 创建每个标签一份的崩溃处置状态。
function createState(now) {
  return {
    reloads: [],                        // 最近自动重载时间戳
    lastAutoReloadAt: 0,
    lastUnresponsiveAt: 0,
    crashedAt: 0,
    goneReason: '',
    circuitOpenUntil: 0,                // 熔断结束时间，此前不再自动重载
    consecutiveCrashes: 0,
  };
}

// decideReload 依据当前状态与时间决定一次崩溃后是否自动重载。
// options: windowMs / maxAutoReloads / reloadCooldownMs / circuitBreakMs
// 返回：
//   { action: 'reload' | 'error-page', state, reason }
function decideReload(state, url, now, options) {
  const opts = options || {};
  const windowMs = opts.windowMs || DEFAULT_WINDOW_MS;
  const max = opts.maxAutoReloads == null ? DEFAULT_MAX_AUTO_RELOADS : opts.maxAutoReloads;
  const cooldown = opts.reloadCooldownMs == null ? DEFAULT_RELOAD_COOLDOWN_MS : opts.reloadCooldownMs;
  const circuitBreakMs = opts.circuitBreakMs || windowMs * 3;
  const st = state || createState(now);

  st.crashedAt = now;
  st.consecutiveCrashes += 1;

  // 熔断期内：直接给错误页，不重载。
  if (st.circuitOpenUntil > now) {
    return { action: 'error-page', state: st, reason: 'circuit-open' };
  }

  if (!isReloadable(url)) {
    return { action: 'error-page', state: st, reason: 'not-reloadable' };
  }

  // 清掉窗口外的旧计数。
  st.reloads = st.reloads.filter((t) => now - t < windowMs);

  if (st.reloads.length >= max) {
    // 窗口内已达上限：打开熔断，停止自动重载。
    st.circuitOpenUntil = now + circuitBreakMs;
    return { action: 'error-page', state: st, reason: 'rate-limit' };
  }

  if (st.lastAutoReloadAt !== 0 && now - st.lastAutoReloadAt < cooldown) {
    return { action: 'error-page', state: st, reason: 'cooldown' };
  }

  st.reloads.push(now);
  st.lastAutoReloadAt = now;
  return { action: 'reload', state: st, reason: 'auto-reload' };
}

// noteRecovery 在页面成功恢复 / 用户手动导航后调用，复位连续崩溃计数。
function noteRecovery(state, now) {
  if (!state) return state;
  // 距上次崩溃超过一个窗口，认为页面已稳定，清熔断与计数。
  if (state.crashedAt && now - state.crashedAt > (state._windowMs || DEFAULT_WINDOW_MS)) {
    state.consecutiveCrashes = 0;
    state.circuitOpenUntil = 0;
  }
  state.lastUnresponsiveAt = 0;
  return state;
}

// decideUnresponsive 决定无响应事件是否应提示用户（冷却去抖）。
function decideUnresponsive(state, now, cooldownMs) {
  const cd = cooldownMs == null ? DEFAULT_UNRESPONSIVE_COOLDOWN_MS : cooldownMs;
  const st = state || createState(now);
  if (st.lastUnresponsiveAt !== 0 && now - st.lastUnresponsiveAt < cd) {
    return { notify: false, state: st };
  }
  st.lastUnresponsiveAt = now;
  return { notify: true, state: st };
}

// describeReason 给出稳定中文说明，用于错误页 / 安全事件（不含 URL）。
function describeReason(reason) {
  const map = {
    'circuit-open': '页面反复崩溃，已停止自动重载',
    'not-reloadable': '崩溃页面不支持自动恢复，请手动打开',
    'rate-limit': '短时间内崩溃次数过多，已停止自动重载',
    'cooldown': '重载间隔过短，已暂停自动恢复',
    'auto-reload': '页面崩溃，正在自动恢复',
  };
  return Object.prototype.hasOwnProperty.call(map, reason) ? map[reason] : '页面崩溃';
}

module.exports = {
  createState,
  decideReload,
  decideUnresponsive,
  noteRecovery,
  isReloadable,
  describeReason,
  RELOADABLE_SCHEMES,
  DEFAULT_WINDOW_MS,
  DEFAULT_MAX_AUTO_RELOADS,
  DEFAULT_RELOAD_COOLDOWN_MS,
  DEFAULT_UNRESPONSIVE_COOLDOWN_MS,
};
