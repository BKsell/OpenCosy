'use strict';

// findguard.js —— 页内查找（Ctrl+F → findInPage）IPC 请求的输入与频率收口内核。
//
// 威胁模型：
//   'find-in-page' IPC 由可信 UI（快捷键栏/查找框）发起，但查询串与触发频率最终来自
//   用户输入 / 渲染层按键事件，可能被构造为：
//     1) 超长字符串：粘贴几十万字符的查询，Chromium 对超长 query 的匹配开销显著，
//        配合高频调用可拖慢渲染进程（DoS）；
//     2) 控制字符 / 非字符串：\x00、孤立代理项、数字/对象等异常输入不应透传；
//     3) 按键洪泛：查找框每次输入都触发 findInPage，输入法连击 / 长按退格会在几百毫秒
//        内发出大量请求，造成匹配抖动与 found-in-page 广播风暴；
//     4) 完全相同的连续请求：选项与文本都没变时无需重复调用 findInPage。
//   本模块只做纯判定，不触碰 webContents；main.js 在 IPC 处理器里据结果决定是否真正
//   调用 contents.findInPage()。空查询（清空查找框）是正常交互，返回 SKIP_EMPTY 由
//   调用方直接清理选中态，不算安全事件。

const FIND_RUN = 'run';               // 正常调用 findInPage
const FIND_SKIP_EMPTY = 'skip-empty'; // 空查询：清理选中态即可
const FIND_COALESCE = 'coalesce';     // 与上次有效请求完全相同，合并
const FIND_REJECT = 'reject';         // 非法输入，拒绝

const REJECT_NOT_STRING = 'find-query-not-string';
const REJECT_TOO_LONG = 'find-query-too-long';
const REJECT_CONTROL = 'find-query-control-char';
const HOLD_BURST = 'find-burst-exceeded';
const HOLD_COOLDOWN = 'find-cooldown-active';

const MAX_FIND_QUERY_LEN = 256;
const FIND_BURST_WINDOW_MS = 1_000;
const FIND_BURST_LIMIT = 30;
const FIND_COOLDOWN_MS = 1_500;
// 完全相同的有效请求间隔低于该值时直接合并（长按/输入法重复提交）。
const FIND_DUP_MS = 40;

// normalizeFindQuery 规整查询串：非字符串按非法处理；首尾空白允许（单词边界需要），
// 但剥离除水平空白外的 C0 控制字符与 DEL；返回 { ok, reason, text }。
function normalizeFindQuery(raw) {
  if (typeof raw !== 'string') {
    return { ok: false, reason: REJECT_NOT_STRING, text: '' };
  }
  if (raw.length > MAX_FIND_QUERY_LEN) {
    return { ok: false, reason: REJECT_TOO_LONG, text: '' };
  }
  // 拒绝除水平制表 \x09 外的所有 C0 控制字符（含 NUL/换行/回车/ESC），
  // 它们可能影响匹配或污染日志。
  if (/[\x00-\x08\x0A-\x1F\x7F]/.test(raw)) {
    return { ok: false, reason: REJECT_CONTROL, text: '' };
  }
  return { ok: true, reason: '', text: raw };
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

function createFindState(now) {
  return {
    requestTimes: [],
    cooldownUntil: 0,
    rejectedCount: 0,
    runCount: 0,
    lastText: '',
    lastMatchCase: false,
    lastWholeWord: false,
    lastRunAt: 0,
    createdAt: now || 0,
  };
}

// decideFind 裁决一次页内查找请求。
// input: { text, matchCase?, wholeWord? }
// 返回 { decision, reason, text, matchCase, wholeWord, burstCount, cooldownUntil }。
function decideFind(state, input, now) {
  const inp = input || {};
  const matchCase = !!inp.matchCase;
  const wholeWord = !!inp.wholeWord;
  if (!state) {
    return {
      decision: FIND_REJECT, reason: REJECT_NOT_STRING, text: '',
      matchCase, wholeWord, burstCount: 0, cooldownUntil: 0,
    };
  }

  const norm = normalizeFindQuery(inp.text);
  // 空串 / 纯空白视为清空查找：不调用 findInPage，调用方自行 clearSelection。
  if (norm.ok && norm.text.trim() === '') {
    return {
      decision: FIND_SKIP_EMPTY, reason: '', text: '',
      matchCase, wholeWord, burstCount: 0, cooldownUntil: 0,
    };
  }
  if (!norm.ok) {
    state.rejectedCount += 1;
    return {
      decision: FIND_REJECT, reason: norm.reason, text: '',
      matchCase, wholeWord,
      burstCount: countSince(state.requestTimes, now - FIND_BURST_WINDOW_MS),
      cooldownUntil: state.cooldownUntil > now ? state.cooldownUntil : 0,
    };
  }
  const text = norm.text;

  // 冷却期内拒绝真正执行（空查询/清空不被冷却拦，避免清不掉状态）。
  if (state.cooldownUntil > now) {
    return {
      decision: FIND_REJECT, reason: HOLD_COOLDOWN, text,
      matchCase, wholeWord,
      burstCount: countSince(state.requestTimes, now - FIND_BURST_WINDOW_MS),
      cooldownUntil: state.cooldownUntil,
    };
  }

  // 与上次有效请求文本 + 选项完全相同，且间隔极短：合并掉重复提交。
  if (state.lastRunAt && text === state.lastText && matchCase === state.lastMatchCase &&
      wholeWord === state.lastWholeWord && now - state.lastRunAt < FIND_DUP_MS) {
    return {
      decision: FIND_COALESCE, reason: '', text,
      matchCase, wholeWord,
      burstCount: countSince(state.requestTimes, now - FIND_BURST_WINDOW_MS),
      cooldownUntil: 0,
    };
  }

  state.requestTimes.push(now);
  pruneOlderThan(state.requestTimes, now - FIND_BURST_WINDOW_MS);
  const burstCount = state.requestTimes.length;
  if (burstCount > FIND_BURST_LIMIT) {
    state.cooldownUntil = now + FIND_COOLDOWN_MS;
    return {
      decision: FIND_REJECT, reason: HOLD_BURST, text,
      matchCase, wholeWord, burstCount, cooldownUntil: state.cooldownUntil,
    };
  }

  state.runCount += 1;
  state.lastText = text;
  state.lastMatchCase = matchCase;
  state.lastWholeWord = wholeWord;
  state.lastRunAt = now;
  return {
    decision: FIND_RUN, reason: '', text,
    matchCase, wholeWord, burstCount, cooldownUntil: 0,
  };
}

// resetFind 在 stopFindInPage 时调用，清空“上次有效请求”，允许用户重新查找同一词。
function resetFind(state) {
  if (!state) return;
  state.lastText = '';
  state.lastMatchCase = false;
  state.lastWholeWord = false;
  state.lastRunAt = 0;
}

function resetCooldown(state) {
  if (state) state.cooldownUntil = 0;
}

function describeFindReason(reason) {
  switch (reason) {
    case REJECT_NOT_STRING:
      return '页内查找查询不是合法字符串，已拒绝';
    case REJECT_TOO_LONG:
      return `页内查找查询超过 ${MAX_FIND_QUERY_LEN} 字符上限，已拒绝`;
    case REJECT_CONTROL:
      return '页内查找查询包含非法控制字符，已拒绝';
    case HOLD_BURST:
      return '页内查找请求短时间内过于频繁，已临时限流';
    case HOLD_COOLDOWN:
      return '页内查找冷却期内的重复请求已忽略';
    default:
      return '页内查找请求';
  }
}

module.exports = {
  FIND_RUN,
  FIND_SKIP_EMPTY,
  FIND_COALESCE,
  FIND_REJECT,
  REJECT_NOT_STRING,
  REJECT_TOO_LONG,
  REJECT_CONTROL,
  HOLD_BURST,
  HOLD_COOLDOWN,
  MAX_FIND_QUERY_LEN,
  FIND_BURST_WINDOW_MS,
  FIND_BURST_LIMIT,
  FIND_COOLDOWN_MS,
  FIND_DUP_MS,
  normalizeFindQuery,
  createFindState,
  decideFind,
  resetFind,
  resetCooldown,
  describeFindReason,
};
