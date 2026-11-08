'use strict';

// hoverguard.js —— 鼠标悬停链接（update-target-url）状态栏显示收口内核。
//
// 威胁模型：
//   鼠标悬停在 <a href> 上时，Chromium 用 webContents 的 'update-target-url'
//   把目标地址抛给主进程，浏览器据此在左下角显示“将要打开：https://…”。
//   恶意页面可以滥用这个“地址预告”：
//     1) 伪造信任：状态栏显示一个正规 https 链接，点击时 window.openHandler
//        却被脚本改成 javascript:/data: 或外域（点击劫持 / 钓鱼的经典一环）；
//     2) 换行/控制字符注入：URL 中夹带 \r\n 与终端转义，在多行状态栏里盖掉
//        真实域名，或在被写进日志时伪造记录行；
//     3) 洪泛：JS 经 elementFromPoint / 嵌套元素 / mousemove 高频触发悬停目标
//        变化，打爆到渲染层的 IPC 与日志盘；
//     4) 超长 URL：单行几万字符撑爆状态栏布局。
//   双层裁决：
//     - 软节流：同一目标去重 + 最小刷新间隔，普通快速划动只合并 IPC（hold）；
//     - 硬洪泛：把“每一次事件”（含被合并的 hold）都计入滑动窗口——攻击者即便
//       刷不出新状态栏，高频事件本身仍会在突发/长窗口越限后触发冷却并整体丢弃，
//       防止它用被节流的事件空转拖死主进程。
//   注意：本内核只收敛“展示通道”，真正点击导航仍由 windowOpenHandler /
//   navguard / shellguard 裁决，状态栏永远不被当作授权依据。纯函数，无 DOM 依赖。

const HOVER_SHOW = 'show'; // 内容净化后允许刷新状态栏
const HOVER_HOLD = 'hold'; // 过于频繁或同值重复，合并本次广播
const HOVER_DROP = 'drop'; // 洪泛/冷却期，按攻击行为丢弃

const HOLD_TOO_SOON = 'hover-too-soon';
const HOLD_SAME = 'hover-same-target';
const DROP_BAD = 'hover-bad-target';
const DROP_FLOOD = 'hover-flood-exceeded';
const DROP_COOLDOWN = 'hover-cooldown-active';

const HOVER_MAX_URL_CHARS = 2048;
const HOVER_MIN_INTERVAL_MS = 60;
const HOVER_BURST_WINDOW_MS = 2_000;
// 正常划动经软节流后最多约 33 次真正刷新/2s；这里按“全部事件”计数，余量给到 100。
const HOVER_BURST_LIMIT = 100;
const HOVER_LONG_WINDOW_MS = 30_000;
// 软节流上限约 16.7 次刷新/s，30s 约 500 次；事件总量上限给到 600。
const HOVER_LONG_LIMIT = 600;
const HOVER_COOLDOWN_MS = 5_000;

// 与 consoleguard 同源的控制字符/转义清洗：状态栏文本绝不允许跨行或带 ANSI。
const ANSI_ESCAPE_RE = /\x1b(?:\[[0-9;?:<=>!#$%&()*+\-./ ^~]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|.)/g;
const C0_CONTROL_RE = /[\x00-\x1f\x7f]/g;
const UNICODE_LINE_SEP_RE = new RegExp('[' + String.fromCharCode(0x2028, 0x2029) + ']', 'g');
const ZERO_WIDTH_RE = new RegExp('[' + String.fromCharCode(0x200b) + '-'
  + String.fromCharCode(0x200f) + String.fromCharCode(0x202a) + '-'
  + String.fromCharCode(0x202e) + String.fromCharCode(0x2060, 0xfeff) + ']', 'g');

// sanitizeHoverUrl 返回 { ok, url, truncated, empty }。空字符串是合法清空信号
//（鼠标移出链接时 Chromium 回调 ''），调用方据 empty 隐藏状态栏而非当攻击。
function sanitizeHoverUrl(input) {
  if (typeof input !== 'string') return { ok: false, url: '', truncated: false, empty: false };
  let url = input
    .replace(ANSI_ESCAPE_RE, '')
    .replace(C0_CONTROL_RE, '')
    .replace(UNICODE_LINE_SEP_RE, '')
    .replace(ZERO_WIDTH_RE, '');
  // 零宽字符上一步已整体剥除，这里只修剪两端普通空白；内部空格保留以免改变 URL 判读。
  url = url.trim();
  if (url.length === 0) return { ok: true, url: '', truncated: false, empty: true };

  let truncated = false;
  const chars = Array.from(url);
  if (chars.length > HOVER_MAX_URL_CHARS) {
    url = chars.slice(0, HOVER_MAX_URL_CHARS - 1).join('') + '…';
    truncated = true;
  }
  return { ok: true, url, truncated, empty: false };
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

function createHoverState(now) {
  return {
    times: [],          // 每次事件（含 hold/drop）的时间戳，硬洪泛计数
    shown: 0,
    held: 0,
    dropped: 0,
    lastShownAt: 0,
    lastUrl: '',
    cooldownUntil: 0,
    createdAt: now || 0,
  };
}

function resetForNavigation(state) {
  if (!state) return;
  state.times = [];
  state.lastShownAt = 0;
  state.lastUrl = '';
  state.cooldownUntil = 0;
}

// noteAttempt 记录一次事件并做硬洪泛裁决。返回 null 表示未越限，否则返回裁决信息。
function noteAttempt(state, now) {
  state.times.push(now);
  pruneOlderThan(state.times, now - HOVER_LONG_WINDOW_MS);
  const burst = countSince(state.times, now - HOVER_BURST_WINDOW_MS);
  if (burst > HOVER_BURST_LIMIT || state.times.length > HOVER_LONG_LIMIT) {
    state.cooldownUntil = now + HOVER_COOLDOWN_MS;
    return { reason: DROP_FLOOD, burstCount: burst, longCount: state.times.length };
  }
  return null;
}

// decideHoverUrl 裁决一次 update-target-url。
function decideHoverUrl(state, rawUrl, now) {
  if (!state) throw new TypeError('hoverguard: state required');
  const clean = sanitizeHoverUrl(rawUrl);
  const baseCounts = () => ({
    burstCount: countSince(state.times, now - HOVER_BURST_WINDOW_MS),
    longCount: state.times.length, droppedTotal: state.dropped,
  });

  if (!clean.ok) {
    state.dropped += 1;
    return { action: HOVER_DROP, reason: DROP_BAD, url: '', truncated: false, ...baseCounts() };
  }

  // 冷却期内除清空信号外一律丢弃；清空信号在下面单独放行，避免攻击者让状态栏卡在假地址。
  const inCooldownBefore = state.cooldownUntil > now;
  // 每一次事件都计入硬洪泛（含被软节流合并的）；清空信号也计数，但即便它正好
  // 越限也必须送达——否则状态栏永远清不掉。越限会刷新冷却，随后的普通链接照丢。
  const flood = noteAttempt(state, now);

  if (clean.empty) {
    if (state.lastUrl === '' && state.lastShownAt !== 0) {
      state.held += 1;
      return { action: HOVER_HOLD, reason: HOLD_SAME, url: '', truncated: false, ...baseCounts() };
    }
    state.lastUrl = '';
    state.lastShownAt = now;
    state.shown += 1;
    return { action: HOVER_SHOW, reason: '', url: '', truncated: false, ...baseCounts() };
  }

  if (state.cooldownUntil > now || flood) {
    state.dropped += 1;
    const reason = inCooldownBefore ? DROP_COOLDOWN : (flood ? flood.reason : DROP_COOLDOWN);
    return {
      action: HOVER_DROP, reason,
      url: clean.url, truncated: clean.truncated,
      burstCount: flood ? flood.burstCount : countSince(state.times, now - HOVER_BURST_WINDOW_MS),
      longCount: flood ? flood.longCount : state.times.length,
      cooldownUntil: state.cooldownUntil, droppedTotal: state.dropped,
    };
  }

  // 冷却已过：恢复正常裁决。
  if (state.cooldownUntil > 0 && state.cooldownUntil <= now) state.cooldownUntil = 0;

  if (clean.url === state.lastUrl && now - state.lastShownAt < HOVER_LONG_WINDOW_MS) {
    state.held += 1;
    return { action: HOVER_HOLD, reason: HOLD_SAME, url: clean.url, truncated: clean.truncated, ...baseCounts() };
  }
  if (now - state.lastShownAt < HOVER_MIN_INTERVAL_MS && state.lastShownAt !== 0) {
    state.held += 1;
    return { action: HOVER_HOLD, reason: HOLD_TOO_SOON, url: clean.url, truncated: clean.truncated, ...baseCounts() };
  }

  state.shown += 1;
  state.lastUrl = clean.url;
  state.lastShownAt = now;
  return { action: HOVER_SHOW, reason: '', url: clean.url, truncated: clean.truncated, ...baseCounts() };
}

function describeHoverReason(reason) {
  switch (reason) {
    case HOLD_TOO_SOON:
      return '悬停目标更新过于频繁，已合并本次状态栏刷新';
    case HOLD_SAME:
      return '悬停目标未变化，状态栏无需刷新';
    case DROP_BAD:
      return '非文本类型的悬停目标已忽略';
    case DROP_FLOOD:
      return '悬停目标变更异常频繁（疑似点击劫持/洪泛），冷却期内停止预告';
    case DROP_COOLDOWN:
      return '悬停洪泛冷却期内的目标变更已忽略';
    default:
      return '悬停目标';
  }
}

module.exports = {
  HOVER_SHOW,
  HOVER_HOLD,
  HOVER_DROP,
  HOLD_TOO_SOON,
  HOLD_SAME,
  DROP_BAD,
  DROP_FLOOD,
  DROP_COOLDOWN,
  HOVER_MAX_URL_CHARS,
  HOVER_MIN_INTERVAL_MS,
  HOVER_BURST_WINDOW_MS,
  HOVER_BURST_LIMIT,
  HOVER_LONG_WINDOW_MS,
  HOVER_LONG_LIMIT,
  HOVER_COOLDOWN_MS,
  sanitizeHoverUrl,
  createHoverState,
  resetForNavigation,
  decideHoverUrl,
  describeHoverReason,
};
