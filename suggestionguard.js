'use strict';

// suggestionguard.js —— 地址栏搜索建议（OpenSearch osjson）响应的有界解析内核。
//
// 威胁模型：
//   主进程固定向 Bing osjson 接口请求建议，返回体会被 JSON.parse 后把字符串数组
//   交回渲染层的地址栏下拉。旧实现存在两个面：
//     1. 响应体没有字节上限：response 数据块被无界 push/concat，被劫持或异常的
//        建议接口可以回一个数 GB 的 body，把主进程内存打爆（拒绝服务）；
//     2. 结构与条目校验散落在 IPC 处理里，只判断了“是不是字符串、长度<=100”，
//        没有排除 ASCII 控制字符、没有去重，畸形/控制字符条目会直达输入框渲染。
//
// 本内核是纯函数，不发起网络请求、不接触磁盘，便于穷举单测：
//   - 强制字节上限，超限直接判定拒绝（调用方据此 destroy 连接）；
//   - 固化 OpenSearch 形态：顶层必须是数组，第 2 项（index 1）必须是字符串数组；
//   - 每条建议做 trim、长度上限、ASCII 控制字符排除，并按展示串去重、限量。

const SUGGEST_DEFAULT_MAX_BYTES = 64 * 1024; // 建议接口是极小 JSON，64KiB 远超正常体量
const SUGGEST_DEFAULT_MAX_ITEMS = 8;
const SUGGEST_DEFAULT_ITEM_MAX_CHARS = 100;

const SUGGEST_REJECT = Object.freeze({
  EMPTY: 'empty-body',
  TOO_LARGE: 'body-too-large',
  BAD_ENCODING: 'bad-encoding',
  NOT_ARRAY: 'not-array',
  NO_SUGGESTIONS: 'no-suggestion-array',
  INVALID_JSON: 'invalid-json',
});

function isControlChar(code) {
  return code <= 0x1f || code === 0x7f;
}

// sanitizeSuggestionItem 对单条建议做展示级消毒：
// 非字符串或去除首尾空白后为空 / 超长 / 含 ASCII 控制字符，一律返回空串（丢弃）。
function sanitizeSuggestionItem(raw, itemMaxChars) {
  if (typeof raw !== 'string') return '';
  const s = raw.trim();
  if (!s || s.length > itemMaxChars) return '';
  for (let i = 0; i < s.length; i += 1) {
    if (isControlChar(s.charCodeAt(i))) return '';
  }
  return s;
}

// toInputBytes 把 Buffer / Uint8Array / 字符串统一成字节计数与 UTF-8 文本。
// 字符串按 UTF-8 重新编码计数，避免调用方用 JS 的 UTF-16 长度低估字节体积。
function toInputBytes(input) {
  if (Buffer.isBuffer(input)) return { buf: input, bytes: input.length };
  if (input instanceof Uint8Array) {
    const buf = Buffer.from(input.buffer, input.byteOffset, input.byteLength);
    return { buf, bytes: buf.length };
  }
  if (typeof input === 'string') {
    const buf = Buffer.from(input, 'utf8');
    return { buf, bytes: buf.length };
  }
  return null;
}

// parseOpenSearchSuggestions 解析一个完整的 osjson 响应体。
// options: { maxBytes, maxItems, itemMaxChars }，缺省取本模块常量。
// 返回 { ok: true, suggestions: string[] } 或 { ok: false, reason }。
function parseOpenSearchSuggestions(input, options) {
  const opts = options || {};
  const maxBytes = typeof opts.maxBytes === 'number' && opts.maxBytes > 0
    ? opts.maxBytes : SUGGEST_DEFAULT_MAX_BYTES;
  const maxItems = typeof opts.maxItems === 'number' && opts.maxItems > 0
    ? opts.maxItems : SUGGEST_DEFAULT_MAX_ITEMS;
  const itemMaxChars = typeof opts.itemMaxChars === 'number' && opts.itemMaxChars > 0
    ? opts.itemMaxChars : SUGGEST_DEFAULT_ITEM_MAX_CHARS;

  const conv = toInputBytes(input);
  if (!conv) return { ok: false, reason: SUGGEST_REJECT.BAD_ENCODING };
  if (conv.bytes === 0) return { ok: false, reason: SUGGEST_REJECT.EMPTY };
  if (conv.bytes > maxBytes) return { ok: false, reason: SUGGEST_REJECT.TOO_LARGE };

  let data;
  try {
    data = JSON.parse(conv.buf.toString('utf8'));
  } catch {
    return { ok: false, reason: SUGGEST_REJECT.INVALID_JSON };
  }
  if (!Array.isArray(data)) return { ok: false, reason: SUGGEST_REJECT.NOT_ARRAY };
  if (!Array.isArray(data[1])) return { ok: false, reason: SUGGEST_REJECT.NO_SUGGESTIONS };

  const out = [];
  const seen = new Set();
  for (const raw of data[1]) {
    const s = sanitizeSuggestionItem(raw, itemMaxChars);
    if (!s) continue;
    // 按展示串精确去重，保留首次出现顺序。
    if (seen.has(s)) continue;
    seen.add(s);
    out.push(s);
    if (out.length >= maxItems) break;
  }
  return { ok: true, suggestions: out };
}

// createByteBudget 生成一个有状态的流式字节累加器：在接收 response 数据块时
// 逐块判定是否已超上限。返回 { accept(chunk), bytes, exceeded }。
// 一旦超限，accept 返回 false 且置 exceeded=true，调用方应立即 destroy 响应，
// 不再拼接后续数据块（真正在网络层止损，而不是收完再丢弃）。
function createByteBudget(maxBytes) {
  const limit = typeof maxBytes === 'number' && maxBytes > 0
    ? maxBytes : SUGGEST_DEFAULT_MAX_BYTES;
  let bytes = 0;
  let exceeded = false;
  return {
    limit,
    accept(chunk) {
      if (exceeded) return false;
      const len = chunk && typeof chunk.length === 'number' ? chunk.length : 0;
      bytes += len;
      if (bytes > limit) {
        exceeded = true;
        return false;
      }
      return true;
    },
    get bytes() { return bytes; },
    get exceeded() { return exceeded; },
  };
}

module.exports = {
  SUGGEST_DEFAULT_MAX_BYTES,
  SUGGEST_DEFAULT_MAX_ITEMS,
  SUGGEST_DEFAULT_ITEM_MAX_CHARS,
  SUGGEST_REJECT,
  sanitizeSuggestionItem,
  parseOpenSearchSuggestions,
  createByteBudget,
};
