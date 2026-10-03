'use strict';

// inpageguard.js —— history.pushState/replaceState 触发的同文档导航收口内核。
//
// 威胁模型：
//   SPA / 恶意页可以在脚本里高频调用 history.pushState()，Electron 主进程每次都会收到
//   'did-navigate-in-page'，旧实现逐条执行 pushNavState()（更新地址栏、压历史栈）并
//   重新应用缩放。恶意页借此：
//     1) 用 history.pushState 循环刷屏，制造地址栏 / 历史记录 / IPC 广播风暴（DoS）；
//     2) 塞入超长 URL 或含控制字符的片段，污染历史存储与地址栏；
//     3) 反复压入仅 hash/query 微差的地址，撑大历史栈，让“后退”几乎失效（历史劫持）。
//   本模块为纯判定：
//     - sanitizeInPageUrl 校验 scheme（仅 http/https/cosy）、长度、控制字符，返回规范化串；
//     - decideInPageNav 做“完全相同 URL 去抖 + 滑动窗口频率收敛”；
//     - 主框架真实跳转（did-navigate）后调 resetForNavigation 清零，给新页面完整额度。

const INPAGE_ACCEPT = 'accept';
const INPAGE_HOLD = 'hold';
const INPAGE_REJECT = 'reject';

const REJECT_BAD_URL = 'inpage-bad-url';
const REJECT_SCHEME = 'inpage-bad-scheme';
const REJECT_TOO_LONG = 'inpage-url-too-long';
const REJECT_CONTROL = 'inpage-url-control';
const HOLD_DUPLICATE = 'inpage-duplicate-url';
const HOLD_BURST = 'inpage-burst-exceeded';
const HOLD_COOLDOWN = 'inpage-cooldown-active';

const MAX_INPAGE_URL_LEN = 8_192;
const INPAGE_BURST_WINDOW_MS = 2_000;
const INPAGE_BURST_LIMIT = 40;
const INPAGE_LONG_WINDOW_MS = 15_000;
const INPAGE_LONG_LIMIT = 200;
const INPAGE_COOLDOWN_MS = 1_500;
// 完全相同 URL 的去抖窗口（pushState 重复压同一地址）。
const INPAGE_DUP_MS = 30;

const ALLOWED_PROTOCOLS = new Set(['http:', 'https:', 'cosy:']);

// sanitizeInPageUrl 校验同文档导航的目标 URL。
// 返回 { ok, reason, url }。
function sanitizeInPageUrl(raw) {
  if (typeof raw !== 'string' || raw.length === 0) {
    return { ok: false, reason: REJECT_BAD_URL, url: '' };
  }
  if (raw.length > MAX_INPAGE_URL_LEN) {
    return { ok: false, reason: REJECT_TOO_LONG, url: '' };
  }
  if (/[\x00-\x1F\x7F]/.test(raw)) {
    return { ok: false, reason: REJECT_CONTROL, url: '' };
  }
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return { ok: false, reason: REJECT_BAD_URL, url: '' };
  }
  if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
    return { ok: false, reason: REJECT_SCHEME, url: '' };
  }
  return { ok: true, reason: '', url: parsed.href };
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

function createInPageState(now) {
  return {
    navTimes: [],
    acceptedCount: 0,
    heldCount: 0,
    rejectedCount: 0,
    cooldownUntil: 0,
    lastUrl: '',
    lastAcceptedAt: 0,
    createdAt: now || 0,
  };
}

function resetForNavigation(state) {
  if (!state) return;
  state.navTimes = [];
  state.cooldownUntil = 0;
  state.lastUrl = '';
  state.lastAcceptedAt = 0;
}

// decideInPageNav 裁决一次 did-navigate-in-page。
// 返回 { decision, reason, url, burstCount, longCount, cooldownUntil }。
function decideInPageNav(state, rawUrl, now) {
  const norm = sanitizeInPageUrl(rawUrl);
  if (!state) {
    return {
      decision: norm.ok ? INPAGE_HOLD : INPAGE_REJECT,
      reason: norm.ok ? HOLD_BURST : norm.reason,
      url: norm.url, burstCount: 0, longCount: 0, cooldownUntil: 0,
    };
  }
  if (!norm.ok) {
    state.rejectedCount += 1;
    return {
      decision: INPAGE_REJECT, reason: norm.reason, url: '',
      burstCount: countSince(state.navTimes, now - INPAGE_BURST_WINDOW_MS),
      longCount: state.navTimes.length,
      cooldownUntil: state.cooldownUntil > now ? state.cooldownUntil : 0,
    };
  }
  const url = norm.url;

  if (state.cooldownUntil > now) {
    state.heldCount += 1;
    return {
      decision: INPAGE_HOLD, reason: HOLD_COOLDOWN, url,
      burstCount: countSince(state.navTimes, now - INPAGE_BURST_WINDOW_MS),
      longCount: state.navTimes.length, cooldownUntil: state.cooldownUntil,
    };
  }

  // 完全相同地址在极短时间内重复压栈：合并（仍可接受首次，重复的不入历史）。
  if (state.lastAcceptedAt && url === state.lastUrl &&
      now - state.lastAcceptedAt < INPAGE_DUP_MS) {
    state.heldCount += 1;
    return {
      decision: INPAGE_HOLD, reason: HOLD_DUPLICATE, url,
      burstCount: countSince(state.navTimes, now - INPAGE_BURST_WINDOW_MS),
      longCount: state.navTimes.length, cooldownUntil: 0,
    };
  }

  state.navTimes.push(now);
  pruneOlderThan(state.navTimes, now - INPAGE_LONG_WINDOW_MS);
  const longCount = state.navTimes.length;
  const burstCount = countSince(state.navTimes, now - INPAGE_BURST_WINDOW_MS);

  if (burstCount > INPAGE_BURST_LIMIT || longCount > INPAGE_LONG_LIMIT) {
    state.cooldownUntil = now + INPAGE_COOLDOWN_MS;
    state.heldCount += 1;
    return {
      decision: INPAGE_HOLD, reason: HOLD_BURST, url,
      burstCount, longCount, cooldownUntil: state.cooldownUntil,
    };
  }

  state.acceptedCount += 1;
  state.lastUrl = url;
  state.lastAcceptedAt = now;
  return {
    decision: INPAGE_ACCEPT, reason: '', url,
    burstCount, longCount, cooldownUntil: 0,
  };
}

function resetCooldown(state) {
  if (state) state.cooldownUntil = 0;
}

function describeInPageReason(reason) {
  switch (reason) {
    case REJECT_BAD_URL:
      return '同文档导航目标不是合法 URL，已忽略';
    case REJECT_SCHEME:
      return '同文档导航使用了不允许的协议，已忽略';
    case REJECT_TOO_LONG:
      return `同文档导航 URL 超过 ${MAX_INPAGE_URL_LEN} 字符上限，已忽略`;
    case REJECT_CONTROL:
      return '同文档导航 URL 含控制字符，已忽略';
    case HOLD_DUPLICATE:
      return '网页短时间重复压入相同地址，已合并';
    case HOLD_BURST:
      return '网页高频修改历史记录（历史劫持/刷屏），已临时收敛';
    case HOLD_COOLDOWN:
      return '同文档导航冷却期内的重复更新已忽略';
    default:
      return '同文档导航';
  }
}

module.exports = {
  INPAGE_ACCEPT,
  INPAGE_HOLD,
  INPAGE_REJECT,
  REJECT_BAD_URL,
  REJECT_SCHEME,
  REJECT_TOO_LONG,
  REJECT_CONTROL,
  HOLD_DUPLICATE,
  HOLD_BURST,
  HOLD_COOLDOWN,
  MAX_INPAGE_URL_LEN,
  INPAGE_BURST_WINDOW_MS,
  INPAGE_BURST_LIMIT,
  INPAGE_LONG_WINDOW_MS,
  INPAGE_LONG_LIMIT,
  INPAGE_COOLDOWN_MS,
  INPAGE_DUP_MS,
  sanitizeInPageUrl,
  createInPageState,
  resetForNavigation,
  decideInPageNav,
  resetCooldown,
  describeInPageReason,
};
