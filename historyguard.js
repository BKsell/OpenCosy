'use strict';

// historyguard.js —— 浏览器本地导航历史的“写入净化 + 有界维护 + 时间范围清理”内核。
//
// 威胁模型：
//   OpenCosy 会把用户访问过的页面（url + title）落到 userData/history.json。旧实现
//   addToHistory 只用 isSafeUrl 挡 URL，title 原样写入，存在几个真实面：
//     1. title 来自远端、完全不可信：可塞入 NUL / CR / LF / 制表符等控制字符污染
//        history.json 的文本展示与后续导出，也可塞入数万字符的超长标题，把历史文件
//        和历史侧栏内存撑大（存储型 DoS）。
//     2. url 即使“安全”，也应只记录 http/https 导航；about:/chrome:/devtools:/
//        file:/view-source: 等内部或本地 scheme 不应混进可被搜索 / 导出的站点历史，
//        否则会泄露本地路径与内部页使用情况。
//     3. 同一 URL 在短时间内被反复刷新会反复 unshift + 写盘，既抖动又放大写放大；
//        同 URL 再次访问应当合并（更新时间戳、提到最前）而不是产生重复条目。
//     4. 历史条目必须有硬上界，且“清除最近一段时间”需要一个可穷举的纯函数裁决，
//        避免 UI 传入反向 / 越界时间范围时漏删或误删。
//   本内核只做纯函数，不碰文件系统与 Electron API，便于穷举单测；main.js 的
//   addToHistory / 时间范围清理复用这里的裁决。

// 历史中允许记录的协议（站点导航）。其余 scheme 一律不入历史。
const ALLOWED_PROTOCOLS = Object.freeze(['http:', 'https:']);
// 单条标题最大字符数（按 code unit 计，足够任何正常标签标题，又能挡住超长灌入）。
const MAX_TITLE_CHARS = 300;
// 单条 URL 最大字符数；超过的不记录（异常/超长跟踪链接不进历史）。
const MAX_URL_CHARS = 8192;
// 默认历史条目总条数硬上界，超出淘汰最旧（数组尾部）。
const MAX_HISTORY_ITEMS = 5000;
// 同一 URL 两次访问若间隔小于该窗口，则合并为一次（仅更新时间戳），抑制刷新抖动。
const MERGE_WINDOW_MS = 10 * 1000;

const DECISION_STORE = 'store';
const DECISION_MERGE = 'merge';
const DECISION_SKIP = 'skip';

const SKIP_BAD_URL = 'bad-url';
const SKIP_BAD_PROTOCOL = 'disallowed-protocol';
const SKIP_TOO_LONG = 'too-long';
const SKIP_EMPTY = 'empty';

const constants = Object.freeze({
  ALLOWED_PROTOCOLS,
  MAX_TITLE_CHARS,
  MAX_URL_CHARS,
  MAX_HISTORY_ITEMS,
  MERGE_WINDOW_MS,
  DECISION_STORE,
  DECISION_MERGE,
  DECISION_SKIP,
  SKIP_BAD_URL,
  SKIP_BAD_PROTOCOL,
  SKIP_TOO_LONG,
  SKIP_EMPTY,
});

// stripControlChars 去掉会破坏文本展示 / 文件行结构的控制字符，保留正常空白与
// Unicode。NUL 一并移除，避免被 C 风格字符串截断的下游误读。
function stripControlChars(s) {
  return String(s).replace(/[\u0000-\u001F\u007F]/g, '');
}

// collapseSpaces 把连续空白（含被保留的普通空格）压成单个空格并去掉首尾空白，
// 防止用大量空白做视觉填充。
function collapseSpaces(s) {
  return s.replace(/\s+/g, ' ').trim();
}

// sanitizeHistoryTitle 清洗页面标题：非字符串给空串、去控制字符、压空白、截断上界。
function sanitizeHistoryTitle(rawTitle) {
  let t = typeof rawTitle === 'string' ? rawTitle : '';
  // 先把制表 / 换行 / 回车归一为普通空格，再删除其余控制字符，最后压缩连续空白。
  t = t.replace(/[\t\n\r]+/g, ' ');
  t = collapseSpaces(stripControlChars(t));
  if (t.length > MAX_TITLE_CHARS) t = t.slice(0, MAX_TITLE_CHARS);
  return t;
}

// sanitizeHistoryUrl 校验并规范化历史可记录的 URL。
// 返回 {ok,url,reason}：只接受 http/https、可解析、长度有界、host 非空的地址。
function sanitizeHistoryUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.length === 0) {
    return { ok: false, url: '', reason: SKIP_EMPTY };
  }
  if (rawUrl.length > MAX_URL_CHARS) {
    return { ok: false, url: '', reason: SKIP_TOO_LONG };
  }
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    return { ok: false, url: '', reason: SKIP_BAD_URL };
  }
  if (!ALLOWED_PROTOCOLS.includes(u.protocol)) {
    return { ok: false, url: '', reason: SKIP_BAD_PROTOCOL };
  }
  if (!u.hostname) {
    return { ok: false, url: '', reason: SKIP_BAD_URL };
  }
  return { ok: true, url: u.href, reason: '' };
}

// createHistoryState 生成一份独立的历史状态（items 为新到旧的有序数组）。
function createHistoryState(initialItems) {
  const items = Array.isArray(initialItems) ? initialItems.slice(0, MAX_HISTORY_ITEMS) : [];
  return { items };
}

// findIndexByUrl 在状态中查找某 URL 的下标，找不到返回 -1。
function findIndexByUrl(state, url) {
  for (let i = 0; i < state.items.length; i++) {
    if (state.items[i].url === url) return i;
  }
  return -1;
}

// capItems 把历史裁剪到硬上界（丢弃数组尾部最旧条目），返回被丢弃数量。
function capItems(state) {
  if (state.items.length <= MAX_HISTORY_ITEMS) return 0;
  const dropped = state.items.length - MAX_HISTORY_ITEMS;
  state.items.length = MAX_HISTORY_ITEMS;
  return dropped;
}

// decideHistoryWrite 决定一次导航如何写入历史。input {url,title}，now 为时间戳。
// 返回 {decision,reason,items?}：
//   store：新条目已 unshift；merge：命中同 URL 且在合并窗内，仅刷新时间戳/标题；
//   skip：不记录（带 reason）。调用方据此决定是否需要落盘（merge/store 需要）。
function decideHistoryWrite(state, input, now) {
  if (!state) return { decision: DECISION_SKIP, reason: SKIP_BAD_URL };
  const su = sanitizeHistoryUrl(input && input.url);
  if (!su.ok) return { decision: DECISION_SKIP, reason: su.reason };
  const title = sanitizeHistoryTitle(input && input.title);

  const idx = findIndexByUrl(state, su.url);
  if (idx !== -1) {
    const existing = state.items[idx];
    // 合并窗内的重复访问：只更新时间戳与标题并提到最前，不新增条目，抑制写抖动。
    if (existing.timestamp >= 0 && now - existing.timestamp < MERGE_WINDOW_MS) {
      existing.timestamp = now;
      if (title) existing.title = title;
      state.items.splice(idx, 1);
      state.items.unshift(existing);
      return { decision: DECISION_MERGE, reason: '' };
    }
    // 窗外的再次访问：移除旧记录，作为一条新访问落到最前（保持“最近访问”语义）。
    state.items.splice(idx, 1);
  }

  state.items.unshift({ url: su.url, title, timestamp: now });
  capItems(state);
  return { decision: DECISION_STORE, reason: '' };
}

// pruneHistoryByTime 删除时间戳落在 [from,to]（闭区间，毫秒）内的条目。
// 返回被删除条目数。对反向 / 非法范围返回 -1 表示拒绝执行（交给调用方提示），
// 不做“悄悄交换端点”，以免 UI 传错时清理范围与用户预期不符。
function pruneHistoryByTime(state, from, to) {
  if (!state || typeof from !== 'number' || typeof to !== 'number'
      || !Number.isFinite(from) || !Number.isFinite(to) || from < 0 || to < 0 || from > to) {
    return -1;
  }
  let removed = 0;
  state.items = state.items.filter((it) => {
    const inside = typeof it.timestamp === 'number' && it.timestamp >= from && it.timestamp <= to;
    if (inside) removed += 1;
    return !inside;
  });
  return removed;
}

// clearAllHistory 清空全部历史，返回被清除条目数。
function clearAllHistory(state) {
  const n = state ? state.items.length : 0;
  if (state) state.items = [];
  return n;
}

module.exports = Object.freeze(Object.assign({
  stripControlChars,
  collapseSpaces,
  sanitizeHistoryTitle,
  sanitizeHistoryUrl,
  createHistoryState,
  findIndexByUrl,
  capItems,
  decideHistoryWrite,
  pruneHistoryByTime,
  clearAllHistory,
}, constants));
