'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'empty',
  NOT_TEXT: 'not-text',
  NUL_STRIPPED: 'nul-stripped',
  CONTROL_STRIPPED: 'control-stripped',
  TOO_LARGE: 'too-large',
  TOO_MANY_LINES: 'too-many-lines',
  TRUNCATED: 'truncated',
};

const MAX_BYTES = 1024 * 1024;
const MAX_LINES = 10000;
const MAX_OUTPUT_BYTES = 256 * 1024;

function byteLength(text) {
  return Buffer.byteLength(text, 'utf8');
}

function countLines(text) {
  let lines = 1;
  for (let i = 0; i < text.length; i += 1) {
    if (text.charCodeAt(i) === 0x0a) lines += 1;
  }
  return lines;
}

function sanitizeClipboardText(value, limits) {
  const options = limits || {};
  const maxBytes = options.maxBytes || MAX_BYTES;
  const maxLines = options.maxLines || MAX_LINES;
  if (typeof value !== 'string') return { ok: false, reason: REASON.NOT_TEXT, text: '', changed: false };
  if (!value) return { ok: false, reason: REASON.EMPTY, text: '', changed: false };
  if (byteLength(value) > maxBytes) return { ok: false, reason: REASON.TOO_LARGE, text: '', changed: false };
  if (countLines(value) > maxLines) return { ok: false, reason: REASON.TOO_MANY_LINES, text: '', changed: false };
  let hadNul = false;
  let hadControl = false;
  let cleaned = '';
  const chars = [];
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code === 0) {
      hadNul = true;
      continue;
    }
    if (code === 0x09 || code === 0x0a || code === 0x0d) {
      chars.push(value[i]);
      continue;
    }
    if (code < 0x20 || code === 0x7f) {
      hadControl = true;
      chars.push(' ');
      continue;
    }
    chars.push(value[i]);
  }
  cleaned = chars.join('').replace(/\r\n/g, '\n');
  let truncated = false;
  if (byteLength(cleaned) > MAX_OUTPUT_BYTES) {
    let cut = cleaned.length;
    while (cut > 0 && byteLength(cleaned.slice(0, cut)) > MAX_OUTPUT_BYTES) cut -= 1;
    cleaned = cleaned.slice(0, cut);
    truncated = true;
  }
  const changed = hadNul || hadControl || truncated;
  if (hadNul) return { ok: true, reason: REASON.NUL_STRIPPED, text: cleaned, changed };
  if (hadControl) return { ok: true, reason: REASON.CONTROL_STRIPPED, text: cleaned, changed };
  if (truncated) return { ok: false, reason: REASON.TRUNCATED, text: cleaned, changed };
  return { ok: true, reason: REASON.OK, text: cleaned, changed };
}

function applyClipboardTextGuard(value, limits) {
  const result = sanitizeClipboardText(value, limits);
  return { changed: result.changed, reason: result.reason, text: result.text };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.EMPTY:
      return '剪贴板内容为空';
    case REASON.NOT_TEXT:
      return '剪贴板内容不是文本';
    case REASON.NUL_STRIPPED:
      return '剪贴板文本含空字节已清除';
    case REASON.CONTROL_STRIPPED:
      return '剪贴板文本含控制字符已替换';
    case REASON.TOO_LARGE:
      return '剪贴板文本超过体积上限';
    case REASON.TOO_MANY_LINES:
      return '剪贴板文本行数过多';
    case REASON.TRUNCATED:
      return '剪贴板文本超过输出上限已截断';
    default:
      return '剪贴板文本合法';
  }
}

module.exports = {
  REASON,
  MAX_BYTES,
  MAX_LINES,
  MAX_OUTPUT_BYTES,
  sanitizeClipboardText,
  applyClipboardTextGuard,
  describeReason,
};
