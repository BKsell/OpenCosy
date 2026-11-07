'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  LEGACY: 'legacy-encoding',
  MULTI_VALUE: 'multi-value',
};

const HEADER = 'content-transfer-encoding';
const MAX_VALUE_LENGTH = 64;
const SAFE = new Set(['binary', '8bit', '7bit']);
const LEGACY = new Set(['base64', 'quoted-printable', 'uuencode', 'x-uuencode']);

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function firstValue(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return '';
  const raw = headers[key];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === 'string' ? value : '';
}

function countValues(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return 0;
  const raw = headers[key];
  if (Array.isArray(raw)) return raw.length;
  return typeof raw === 'string' ? 1 : 0;
}

function parseTransferEncoding(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, token: null };
  const text = value.trim().toLowerCase();
  if (!text) return { reason: REASON.MALFORMED, token: null };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG, token: null };
  if (text.includes(',')) return { reason: REASON.MULTI_VALUE, token: null };
  if (SAFE.has(text)) return { reason: REASON.OK, token: text };
  if (LEGACY.has(text)) return { reason: REASON.LEGACY, token: text };
  return { reason: REASON.MALFORMED, token: null };
}

function inspectTransferEncoding(headers) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING, token: null };
  if (countValues(headers, HEADER) > 1) {
    return { changed: true, reason: REASON.MULTI_VALUE, token: null };
  }
  const parsed = parseTransferEncoding(value);
  if (parsed.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, token: parsed.token };
  }
  return { changed: true, reason: parsed.reason, token: parsed.token };
}

function applyTransferEncodingGuard(headers) {
  const result = inspectTransferEncoding(headers);
  if (!result.changed) return result;
  const key = headerKey(headers, HEADER);
  if (key) delete headers[key];
  return result;
}

function describeReason(reason) {
  switch (reason) {
    case REASON.MALFORMED:
      return 'Content-Transfer-Encoding 取值非法，已剥除';
    case REASON.OVERLONG:
      return 'Content-Transfer-Encoding 字段超长，已剥除';
    case REASON.LEGACY:
      return 'HTTP 响应使用 MIME 传统编码，已剥除';
    case REASON.MULTI_VALUE:
      return 'Content-Transfer-Encoding 多头下发，已剥除';
    case REASON.MISSING:
      return '响应未声明 Content-Transfer-Encoding';
    default:
      return 'Content-Transfer-Encoding 为直通编码';
  }
}

module.exports = {
  REASON,
  HEADER,
  MAX_VALUE_LENGTH,
  SAFE,
  LEGACY,
  headerKey,
  firstValue,
  countValues,
  parseTransferEncoding,
  inspectTransferEncoding,
  applyTransferEncodingGuard,
  describeReason,
};
