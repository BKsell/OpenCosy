'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  BAD_UNIT: 'bad-unit',
  BAD_ORDER: 'bad-order',
  BAD_TOTAL: 'bad-total',
  UNSATISFIABLE: 'unsatisfiable',
  LENGTH_MISMATCH: 'length-mismatch',
  UNKNOWN_TOTAL: 'unknown-total',
};

const MAX_VALUE_LENGTH = 128;
const MAX_TOTAL = 9007199254740991;

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

function parseContentRange(value) {
  if (typeof value !== 'string') return null;
  const text = value.trim();
  if (!text) return null;
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG };
  const match = /^bytes\s+(\d{1,16}|\*)\s*-\s*(\d{1,16})\s*\/\s*(\d{1,16}|\*)$/i.exec(text);
  if (!match) {
    if (/^bytes\s+\*\//i.test(text)) return { reason: REASON.UNSATISFIABLE };
    return { reason: REASON.MALFORMED };
  }
  if (match[1] === '*') return { reason: REASON.MALFORMED };
  const start = Number(match[1]);
  const end = Number(match[2]);
  const totalRaw = match[3];
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end)) {
    return { reason: REASON.OVERLONG };
  }
  if (start > end) return { reason: REASON.BAD_ORDER };
  let total = null;
  if (totalRaw !== '*') {
    total = Number(totalRaw);
    if (!Number.isSafeInteger(total)) return { reason: REASON.OVERLONG };
    if (total > MAX_TOTAL) return { reason: REASON.BAD_TOTAL };
    if (end >= total) return { reason: REASON.BAD_TOTAL };
    if (start >= total) return { reason: REASON.BAD_TOTAL };
  }
  return {
    reason: totalRaw === '*' ? REASON.UNKNOWN_TOTAL : REASON.OK,
    start,
    end,
    total,
    length: end - start + 1,
  };
}

function inspectContentRange(headers) {
  const value = firstValue(headers, 'content-range');
  if (!value) return { changed: false, reason: REASON.MISSING, verdict: null };
  const parsed = parseContentRange(value);
  if (!parsed) {
    return { changed: true, reason: REASON.MALFORMED, verdict: null };
  }
  if (parsed.reason === REASON.UNKNOWN_TOTAL) {
    return { changed: false, reason: REASON.UNKNOWN_TOTAL, verdict: parsed };
  }
  if (parsed.reason !== REASON.OK) {
    return { changed: true, reason: parsed.reason, verdict: parsed };
  }
  const lengthRaw = firstValue(headers, 'content-length');
  if (lengthRaw) {
    const trimmed = lengthRaw.trim();
    if (!/^\d{1,16}$/.test(trimmed)) {
      return { changed: true, reason: REASON.LENGTH_MISMATCH, verdict: parsed };
    }
    const declared = Number(trimmed);
    if (Number.isSafeInteger(declared) && declared !== parsed.length) {
      return { changed: true, reason: REASON.LENGTH_MISMATCH, verdict: parsed };
    }
  }
  return { changed: false, reason: REASON.OK, verdict: parsed };
}

function applyContentRangeGuard(headers) {
  const result = inspectContentRange(headers);
  if (!result.changed) return result;
  const key = headerKey(headers, 'content-range');
  if (key) delete headers[key];
  return result;
}

function describeReason(reason) {
  switch (reason) {
    case REASON.MALFORMED:
      return 'Content-Range 格式非法';
    case REASON.OVERLONG:
      return 'Content-Range 过长或数值溢出';
    case REASON.BAD_ORDER:
      return 'Content-Range 起止顺序颠倒';
    case REASON.BAD_TOTAL:
      return 'Content-Range 总长与区间矛盾';
    case REASON.UNSATISFIABLE:
      return 'Content-Range 声明不可满足区间';
    case REASON.LENGTH_MISMATCH:
      return 'Content-Range 与 Content-Length 不一致';
    case REASON.UNKNOWN_TOTAL:
      return 'Content-Range 未声明总长';
    default:
      return 'Content-Range 通过校验';
  }
}

module.exports = {
  REASON,
  MAX_VALUE_LENGTH,
  parseContentRange,
  inspectContentRange,
  applyContentRangeGuard,
  describeReason,
};
