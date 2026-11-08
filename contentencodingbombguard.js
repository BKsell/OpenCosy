'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'empty',
  BASE64: 'base64-encoding',
  UNSUPPORTED: 'unsupported-encoding',
  MULTIPLE: 'multiple-encodings',
  BAD_LENGTH: 'bad-content-length',
  TOO_LARGE: 'too-large',
  UNKNOWN_LENGTH: 'unknown-length',
};

const ALLOWED = new Set(['identity', 'gzip', 'br', 'deflate']);
const MAX_BYTES = 64 * 1024 * 1024;
const MAX_ENCODINGS = 2;

function inspectResponseBody(headers, options) {
  const opts = options || {};
  const maxBytes = opts.maxBytes || MAX_BYTES;
  if (!headers || typeof headers !== 'object') return { ok: false, reason: REASON.EMPTY };
  const rawEncoding = headers['content-encoding'];
  const encodingValue = Array.isArray(rawEncoding) ? rawEncoding[0] : rawEncoding;
  let encodings = [];
  if (typeof encodingValue === 'string' && encodingValue.trim()) {
    encodings = encodingValue.toLowerCase().split(',').map((part) => part.trim()).filter(Boolean);
  }
  if (encodings.includes('base64')) return { ok: false, reason: REASON.BASE64, encodings };
  if (encodings.length > MAX_ENCODINGS) return { ok: false, reason: REASON.MULTIPLE, encodings };
  for (const encoding of encodings) {
    if (!ALLOWED.has(encoding)) return { ok: false, reason: REASON.UNSUPPORTED, encodings };
  }
  const rawLength = headers['content-length'];
  const lengthValue = Array.isArray(rawLength) ? rawLength[0] : rawLength;
  let length = null;
  if (typeof lengthValue === 'string' || typeof lengthValue === 'number') {
    const text = String(lengthValue).trim();
    if (!/^\d{1,18}$/.test(text)) return { ok: false, reason: REASON.BAD_LENGTH, encodings };
    length = Number(text);
    if (length > maxBytes) return { ok: false, reason: REASON.TOO_LARGE, encodings };
  } else if (encodings.length > 0) {
    return { ok: false, reason: REASON.UNKNOWN_LENGTH, encodings };
  }
  return { ok: true, reason: REASON.OK, encodings, length, maxBytes };
}

function applyContentEncodingGuard(headers, options) {
  const result = inspectResponseBody(headers, options);
  return { changed: !result.ok, reason: result.reason, encodings: result.encodings || [], length: result.length };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.EMPTY:
      return '响应头为空';
    case REASON.BASE64:
      return '响应声明了 base64 编码';
    case REASON.UNSUPPORTED:
      return '响应使用不支持的压缩编码';
    case REASON.MULTIPLE:
      return '响应叠加多层压缩编码';
    case REASON.BAD_LENGTH:
      return '响应 Content-Length 非法';
    case REASON.TOO_LARGE:
      return '响应声明体积超过上限';
    case REASON.UNKNOWN_LENGTH:
      return '压缩响应缺少 Content-Length';
    default:
      return '响应编码与长度合法';
  }
}

module.exports = {
  REASON,
  ALLOWED,
  MAX_BYTES,
  MAX_ENCODINGS,
  inspectResponseBody,
  applyContentEncodingGuard,
  describeReason,
};
