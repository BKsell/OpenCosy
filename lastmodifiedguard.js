'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  FUTURE_DATE: 'future-date',
  PRE_EPOCH: 'pre-epoch',
  TOO_OLD: 'too-old',
};

const HEADER = 'last-modified';
const MAX_CLOCK_SKEW_MS = 300000;
const MIN_VALID_STAMP = Date.UTC(1970, 0, 1);
const MAX_AGE_MS = 3650 * 86400000;

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

function parseLastModified(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, stamp: null };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED, stamp: null };
  if (text.length > 64) return { reason: REASON.MALFORMED, stamp: null };
  const stamp = Date.parse(text);
  if (!Number.isFinite(stamp)) return { reason: REASON.MALFORMED, stamp: null };
  if (stamp < MIN_VALID_STAMP) return { reason: REASON.PRE_EPOCH, stamp };
  return { reason: REASON.OK, stamp };
}

function inspectLastModified(headers, nowMs) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING, stamp: null };
  const parsed = parseLastModified(value);
  if (parsed.reason !== REASON.OK) {
    return { changed: true, reason: parsed.reason, stamp: parsed.stamp };
  }
  const now = Number.isFinite(nowMs) ? nowMs : Date.now();
  if (parsed.stamp - now > MAX_CLOCK_SKEW_MS) {
    return { changed: true, reason: REASON.FUTURE_DATE, stamp: parsed.stamp };
  }
  if (now - parsed.stamp > MAX_AGE_MS) {
    return { changed: true, reason: REASON.TOO_OLD, stamp: parsed.stamp };
  }
  return { changed: false, reason: REASON.OK, stamp: parsed.stamp };
}

function applyLastModifiedGuard(headers, nowMs) {
  const result = inspectLastModified(headers, nowMs);
  if (!result.changed) return result;
  const key = headerKey(headers, HEADER);
  if (key) delete headers[key];
  return result;
}

function describeReason(reason) {
  switch (reason) {
    case REASON.MALFORMED:
      return 'Last-Modified 不是合法 HTTP 日期';
    case REASON.FUTURE_DATE:
      return 'Last-Modified 指向未来时间';
    case REASON.PRE_EPOCH:
      return 'Last-Modified 早于 Unix 纪元';
    case REASON.TOO_OLD:
      return 'Last-Modified 超出可接受陈旧期限';
    default:
      return 'Last-Modified 校验通过';
  }
}

module.exports = {
  REASON,
  HEADER,
  MAX_CLOCK_SKEW_MS,
  MAX_AGE_MS,
  headerKey,
  firstValue,
  parseLastModified,
  inspectLastModified,
  applyLastModifiedGuard,
  describeReason,
};
