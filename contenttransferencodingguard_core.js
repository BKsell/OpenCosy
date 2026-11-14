'use strict';
const { describeReasonTable } = require('./reasontext');
const { applySingleHeaderGuard } = require('./guardapply_core');

const { firstValue, headerKey } = require('./headerutil_core');

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
  const result = inspectSingleHeader(headers, HEADER, parseTransferEncoding, REASON.MISSING, REASON.MULTI_VALUE, REASON.OK);
  return { changed: result.changed, reason: result.reason, token: result.parsed ? result.parsed.token : null };
}

function applyTransferEncodingGuard(headers) {
  return applySingleHeaderGuard(headers, HEADER, inspectTransferEncoding);
}

const describeReason = describeReasonTable({
    [REASON.MALFORMED]: 'Content-Transfer-Encoding 取值非法，已剥除',
    [REASON.OVERLONG]: 'Content-Transfer-Encoding 字段超长，已剥除',
    [REASON.LEGACY]: 'HTTP 响应使用 MIME 传统编码，已剥除',
    [REASON.MULTI_VALUE]: 'Content-Transfer-Encoding 多头下发，已剥除',
    [REASON.MISSING]: '响应未声明 Content-Transfer-Encoding',
  }, 'Content-Transfer-Encoding 为直通编码');

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
