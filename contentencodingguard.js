'use strict';
const { describeReasonTable } = require('./reasontext');

const { firstValue, headerKey } = require('./headerutil');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  UNKNOWN_CODING: 'unknown-coding',
  DUPLICATE: 'duplicate',
  TOO_MANY: 'too-many',
};

const ALLOWED_CODINGS = new Set(['gzip', 'x-gzip', 'deflate', 'br', 'zstd', 'identity']);
const MAX_CODINGS = 3;
const MAX_VALUE_LENGTH = 128;

function parseCodings(value) {
  if (typeof value !== 'string') return { codings: [], reason: REASON.MALFORMED };
  const text = value.trim().toLowerCase();
  if (!text) return { codings: [], reason: REASON.MALFORMED };
  if (text.length > MAX_VALUE_LENGTH) return { codings: [], reason: REASON.MALFORMED };
  const codings = text.split(',').map((part) => part.trim()).filter(Boolean);
  if (!codings.length) return { codings: [], reason: REASON.MALFORMED };
  if (codings.length > MAX_CODINGS) return { codings, reason: REASON.TOO_MANY };
  const seen = new Set();
  for (const coding of codings) {
    if (!ALLOWED_CODINGS.has(coding)) {
      return { codings, reason: REASON.UNKNOWN_CODING };
    }
    if (seen.has(coding)) {
      return { codings, reason: REASON.DUPLICATE };
    }
    seen.add(coding);
  }
  return { codings, reason: REASON.OK };
}

function inspectContentEncoding(headers) {
  const value = firstValue(headers, 'content-encoding');
  if (!value) return { changed: false, reason: REASON.MISSING, codings: [] };
  const parsed = parseCodings(value);
  if (parsed.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, codings: parsed.codings };
  }
  return { changed: true, reason: parsed.reason, codings: parsed.codings };
}

function applyContentEncodingGuard(headers) {
  const result = inspectContentEncoding(headers);
  if (!result.changed) return result;
  const key = headerKey(headers, 'content-encoding');
  if (key) delete headers[key];
  const lengthKey = headerKey(headers, 'content-length');
  if (lengthKey && !firstValue(headers, 'content-length').trim()) {
    delete headers[lengthKey];
  }
  return result;
}

const describeReason = describeReasonTable({
    [REASON.MALFORMED]: 'Content-Encoding 取值非法',
    [REASON.UNKNOWN_CODING]: 'Content-Encoding 使用未知压缩算法',
    [REASON.DUPLICATE]: 'Content-Encoding 重复声明同一算法',
    [REASON.TOO_MANY]: 'Content-Encoding 层数超过预算',
    [REASON.MISSING]: '未声明 Content-Encoding',
  }, 'Content-Encoding 通过校验');

module.exports = {
  REASON,
  ALLOWED_CODINGS,
  MAX_CODINGS,
  MAX_VALUE_LENGTH,
  parseCodings,
  inspectContentEncoding,
  applyContentEncodingGuard,
  describeReason,
};
