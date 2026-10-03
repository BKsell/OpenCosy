'use strict';

// entryguard.js —— 导航条目提交事件（webContents 'navigation-entry-committed'）收口内核。
//
// 与 inpageguard 的分工：inpageguard 管“同文档导航（hash / history.pushState）是否允许”
// 的策略层；entryguard 管“条目提交这个事件通道本身”——地址栏据此显示最终 URL，因此要
// 防两件事：
//   1) 地址注入/脏显示：提交条目携带的 URL 若含控制字符（\r\n、ANSI、U+2028/2029），
//      写进地址栏文本或行式日志时可能换行伪造；超长 URL 撑爆地址栏布局；
//   2) 历史条目洪泛：页面用 history.pushState/history.forward 在循环里疯狂提交条目，
//      打爆会话历史与地址栏刷新 IPC（真实 DoS），并做 back-forward 劫持（埋一堆假条目
//      让用户很难回到上一页）。
// 纯函数：只对“可显示 URL 文本 + 提交频率”裁决，不决定导航合法性（那是 navguard/
// inpageguard 的职责）。无 DOM 依赖。

const ENTRY_ACCEPT = 'accept';
const ENTRY_HOLD = 'hold';
const ENTRY_DROP = 'drop';

const HOLD_SAME = 'entry-same-url';
const HOLD_TOO_SOON = 'entry-too-soon';
const DROP_BAD_URL = 'entry-bad-url';
const DROP_FLOOD = 'entry-flood-exceeded';
const DROP_COOLDOWN = 'entry-cooldown-active';

const ENTRY_MAX_URL_CHARS = 4096;
const ENTRY_MIN_INTERVAL_MS = 30;
const ENTRY_BURST_WINDOW_MS = 1_000;
const ENTRY_BURST_LIMIT = 60;
const ENTRY_LONG_WINDOW_MS = 10_000;
const ENTRY_LONG_LIMIT = 400;
const ENTRY_COOLDOWN_MS = 3_000;

const ANSI_ESCAPE_RE = /\x1b(?:\[[0-9;?:<=>!#$%&()*+\-./ ^~]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|.)/g;
const C0_CONTROL_RE = /[\x00-\x1f\x7f]/g;
const UNICODE_LINE_SEP_RE = new RegExp('[' + String.fromCharCode(0x2028, 0x2029) + ']', 'g');
const ZERO_WIDTH_RE = new RegExp('[' + String.fromCharCode(0x200b) + '-'
  + String.fromCharCode(0x200f) + String.fromCharCode(0x202a) + '-'
  + String.fromCharCode(0x202e) + String.fromCharCode(0x2060, 0xfeff) + ']', 'g');

// sanitizeEntryUrl 净化并限长待显示的提交条目 URL。
// 返回 { ok, url, truncated }。控制字符一律剥除；非字符串拒绝。
function sanitizeEntryUrl(input) {
  if (typeof input !== 'string') return { ok: false, url: '', truncated: false };
  let url = input
    .replace(ANSI_ESCAPE_RE, '')
    .replace(C0_CONTROL_RE, '')
    .replace(UNICODE_LINE_SEP_RE, '')
    .replace(ZERO_WIDTH_RE, '')
    .trim();
  if (url.length === 0) return { ok: false, url: '', truncated: false };

  let truncated = false;
  const chars = Array.from(url);
  if (chars.length > ENTRY_MAX_URL_CHARS) {
    url = chars.slice(0, ENTRY_MAX_URL_CHARS - 1).join('') + '…';
    truncated = true;
  }
  return { ok: true, url, truncated };
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

function createEntryState(now) {
  return {
    times: [],
    accepted: 0,
    held: 0,
    dropped: 0,
    lastUrl: '',
    lastAcceptedAt: 0,
    cooldownUntil: 0,
    createdAt: now || 0,
  };
}

function resetForNavigation(state) {
  if (!state) return;
  state.times = [];
  state.lastUrl = '';
  state.lastAcceptedAt = 0;
  state.cooldownUntil = 0;
}

// decideNavigationEntry 裁决一次 navigation-entry-committed。
// 与 hover/theme 不同：这里没有“清空信号”，URL 必须是有效可显示文本。
function decideNavigationEntry(state, rawUrl, now) {
  if (!state) throw new TypeError('entryguard: state required');
  const parsed = sanitizeEntryUrl(rawUrl);
  const counts = () => ({
    burstCount: countSince(state.times, now - ENTRY_BURST_WINDOW_MS),
    longCount: state.times.length, droppedTotal: state.dropped,
  });

  if (!parsed.ok) {
    state.dropped += 1;
    return { action: ENTRY_DROP, reason: DROP_BAD_URL, url: '', ...counts() };
  }

  const inCooldownBefore = state.cooldownUntil > now;
  state.times.push(now);
  pruneOlderThan(state.times, now - ENTRY_LONG_WINDOW_MS);
  const burst = countSince(state.times, now - ENTRY_BURST_WINDOW_MS);
  let flood = null;
  if (burst > ENTRY_BURST_LIMIT || state.times.length > ENTRY_LONG_LIMIT) {
    state.cooldownUntil = now + ENTRY_COOLDOWN_MS;
    flood = { reason: DROP_FLOOD, burstCount: burst, longCount: state.times.length };
  }

  if (state.cooldownUntil > now || flood) {
    state.dropped += 1;
    return {
      action: ENTRY_DROP,
      reason: inCooldownBefore ? DROP_COOLDOWN : (flood ? flood.reason : DROP_COOLDOWN),
      url: parsed.url,
      burstCount: flood ? flood.burstCount : burst,
      longCount: flood ? flood.longCount : state.times.length,
      cooldownUntil: state.cooldownUntil, droppedTotal: state.dropped,
    };
  }
  if (state.cooldownUntil > 0 && state.cooldownUntil <= now) state.cooldownUntil = 0;

  if (parsed.url === state.lastUrl) {
    state.held += 1;
    return { action: ENTRY_HOLD, reason: HOLD_SAME, url: parsed.url, ...counts() };
  }
  if (now - state.lastAcceptedAt < ENTRY_MIN_INTERVAL_MS && state.lastAcceptedAt !== 0) {
    state.held += 1;
    return { action: ENTRY_HOLD, reason: HOLD_TOO_SOON, url: parsed.url, ...counts() };
  }

  state.accepted += 1;
  state.lastUrl = parsed.url;
  state.lastAcceptedAt = now;
  return { action: ENTRY_ACCEPT, reason: '', url: parsed.url, truncated: parsed.truncated, ...counts() };
}

function describeEntryReason(reason) {
  switch (reason) {
    case HOLD_SAME:
      return '导航条目地址未变化，已合并地址栏刷新';
    case HOLD_TOO_SOON:
      return '导航条目提交过于频繁，已合并地址栏刷新';
    case DROP_BAD_URL:
      return '导航条目携带了非法地址文本，已阻止其显示';
    case DROP_FLOOD:
      return '页面异常频繁提交历史条目（疑似历史劫持/洪泛），冷却期内冻结地址栏刷新';
    case DROP_COOLDOWN:
      return '历史条目洪泛冷却期内的提交已忽略';
    default:
      return '导航条目';
  }
}

module.exports = {
  ENTRY_ACCEPT,
  ENTRY_HOLD,
  ENTRY_DROP,
  HOLD_SAME,
  HOLD_TOO_SOON,
  DROP_BAD_URL,
  DROP_FLOOD,
  DROP_COOLDOWN,
  ENTRY_MAX_URL_CHARS,
  ENTRY_MIN_INTERVAL_MS,
  ENTRY_BURST_WINDOW_MS,
  ENTRY_BURST_LIMIT,
  ENTRY_LONG_WINDOW_MS,
  ENTRY_LONG_LIMIT,
  ENTRY_COOLDOWN_MS,
  sanitizeEntryUrl,
  createEntryState,
  resetForNavigation,
  decideNavigationEntry,
  describeEntryReason,
};
