'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  NEGATIVE_AGE: 'negative-age',
  DATE_SKEW: 'date-skew',
  STALE: 'stale',
};

const HEADER_AGE = 'age';
const HEADER_DATE = 'date';
const MAX_AGE_SECONDS = 2147483648;
const MAX_STALE_SECONDS = 604800;
const MAX_DATE_SKEW_SECONDS = 300;

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

function parseAge(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, age: null };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED, age: null };
  if (!/^\d{1,16}$/.test(text)) {
    if (/^[-+]\d+$/.test(text)) return { reason: REASON.NEGATIVE_AGE, age: null };
    return { reason: REASON.MALFORMED, age: null };
  }
  const age = Number(text);
  if (!Number.isSafeInteger(age)) return { reason: REASON.OVERLONG, age: null };
  if (age > MAX_AGE_SECONDS) return { reason: REASON.OVERLONG, age: null };
  return { reason: REASON.OK, age };
}

function parseDate(value) {
  if (typeof value !== 'string') return null;
  const text = value.trim();
  if (!text) return null;
  const stamp = Date.parse(text);
  if (!Number.isFinite(stamp)) return null;
  return stamp;
}

function inspectAgeClock(headers, nowMs) {
  const ageRaw = firstValue(headers, HEADER_AGE);
  const dateRaw = firstValue(headers, HEADER_DATE);
  const now = Number.isFinite(nowMs) ? nowMs : Date.now();
  if (!ageRaw) return { changed: false, reason: REASON.MISSING, age: null };
  const parsed = parseAge(ageRaw);
  if (parsed.reason !== REASON.OK) {
    return { changed: true, reason: parsed.reason, age: null };
  }
  const dateStamp = parseDate(dateRaw);
  if (dateStamp !== null) {
    const skew = Math.floor((dateStamp - now) / 1000);
    if (Math.abs(skew) > MAX_DATE_SKEW_SECONDS) {
      return { changed: true, reason: REASON.DATE_SKEW, age: parsed.age };
    }
  }
  if (parsed.age > MAX_STALE_SECONDS) {
    return { changed: true, reason: REASON.STALE, age: parsed.age };
  }
  if (parsed.age === MAX_AGE_SECONDS) {
    return { changed: true, reason: REASON.OVERLONG, age: parsed.age };
  }
  return { changed: false, reason: REASON.OK, age: parsed.age };
}

function applyAgeClockGuard(headers, nowMs) {
  const result = inspectAgeClock(headers, nowMs);
  if (!result.changed) return result;
  const key = headerKey(headers, HEADER_AGE);
  if (key) delete headers[key];
  return result;
}

function describeReason(reason) {
  switch (reason) {
    case REASON.MALFORMED:
      return 'Age 头不是十进制秒数';
    case REASON.OVERLONG:
      return 'Age 超出合法区间';
    case REASON.NEGATIVE_AGE:
      return 'Age 出现负值或符号前缀';
    case REASON.DATE_SKEW:
      return 'Date 与本地时间偏差超出预算';
    case REASON.STALE:
      return 'Age 表示缓存已过期';
    default:
      return 'Age 与 Date 校验通过';
  }
}

module.exports = {
  REASON,
  HEADER_AGE,
  HEADER_DATE,
  MAX_AGE_SECONDS,
  MAX_STALE_SECONDS,
  MAX_DATE_SKEW_SECONDS,
  headerKey,
  firstValue,
  parseAge,
  parseDate,
  inspectAgeClock,
  applyAgeClockGuard,
  describeReason,
};
