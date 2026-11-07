'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  NEGATIVE: 'negative-value',
  OVERLONG: 'overlong-value',
  BAD_DATE: 'invalid-date',
  TOO_FAR: 'window-too-large',
};

const MAX_DELAY_SECONDS = 86400;
const MAX_VALUE_LENGTH = 64;
const HTTP_DATE = /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/;

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function headerValue(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return null;
  const raw = headers[key];
  return Array.isArray(raw) ? raw[0] : raw;
}

function parseRetryAfter(value, nowMs) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED };
  const text = value.trim();
  if (!text) return { reason: REASON.MISSING };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG };
  if (/^-/.test(text)) return { reason: REASON.NEGATIVE };
  if (/^\d+$/.test(text)) {
    const seconds = Number(text);
    if (!Number.isSafeInteger(seconds)) return { reason: REASON.OVERLONG };
    if (seconds < 0) return { reason: REASON.NEGATIVE };
    if (seconds > MAX_DELAY_SECONDS) return { reason: REASON.TOO_FAR, seconds: MAX_DELAY_SECONDS, clamped: true };
    return { reason: REASON.OK, seconds, clamped: false };
  }
  if (!HTTP_DATE.test(text)) return { reason: REASON.BAD_DATE };
  const parsed = Date.parse(text);
  if (!Number.isFinite(parsed)) return { reason: REASON.BAD_DATE };
  const now = Number.isFinite(nowMs) ? nowMs : Date.now();
  const delta = Math.round((parsed - now) / 1000);
  if (delta < 0) return { reason: REASON.NEGATIVE, seconds: 0, clamped: true };
  if (delta > MAX_DELAY_SECONDS) return { reason: REASON.TOO_FAR, seconds: MAX_DELAY_SECONDS, clamped: true };
  return { reason: REASON.OK, seconds: delta, clamped: false };
}

function applyRetryAfterGuard(headers, nowMs) {
  const key = headerKey(headers, 'retry-after');
  if (!key) return { changed: false, reason: REASON.MISSING, seconds: null };
  const raw = headerValue(headers, 'retry-after');
  const parsed = parseRetryAfter(raw, nowMs);
  switch (parsed.reason) {
    case REASON.OK:
      return { changed: false, reason: REASON.OK, seconds: parsed.seconds };
    case REASON.NEGATIVE:
    case REASON.BAD_DATE:
    case REASON.MALFORMED:
    case REASON.OVERLONG:
      delete headers[key];
      return { changed: true, reason: parsed.reason, seconds: null };
    case REASON.TOO_FAR:
      headers[key] = String(MAX_DELAY_SECONDS);
      return { changed: true, reason: REASON.TOO_FAR, seconds: MAX_DELAY_SECONDS };
    default:
      delete headers[key];
      return { changed: true, reason: parsed.reason, seconds: null };
  }
}

function describeReason(reason) {
  switch (reason) {
    case REASON.MISSING:
      return '未声明 Retry-After';
    case REASON.MALFORMED:
      return 'Retry-After 无法解析，已移除';
    case REASON.NEGATIVE:
      return 'Retry-After 为负数或已过期，已移除';
    case REASON.OVERLONG:
      return 'Retry-After 数值溢出，已移除';
    case REASON.BAD_DATE:
      return 'Retry-After 日期格式非法，已移除';
    case REASON.TOO_FAR:
      return 'Retry-After 等待窗口过长，已截断';
    default:
      return 'Retry-After 通过校验';
  }
}

module.exports = {
  REASON,
  MAX_DELAY_SECONDS,
  MAX_VALUE_LENGTH,
  parseRetryAfter,
  applyRetryAfterGuard,
  describeReason,
};
