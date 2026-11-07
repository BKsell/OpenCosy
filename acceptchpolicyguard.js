'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  TOO_MANY: 'too-many-hints',
  CRITICAL_UNKNOWN: 'critical-not-in-accept',
  CRITICAL_EMPTY: 'critical-empty',
  OVERLONG: 'overlong',
};

const HEADER_ACCEPT = 'accept-ch';
const HEADER_CRITICAL = 'critical-ch';
const MAX_HINTS = 16;
const MAX_HINT_LENGTH = 32;
const MAX_FIELD_LENGTH = 256;
const HINT_TOKEN = /^[a-z][a-z0-9-]{1,31}$/;

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function tokensOf(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return { raw: '', tokens: [] };
  const raw = headers[key];
  const value = Array.isArray(raw) ? raw.join(',') : raw;
  if (typeof value !== 'string') return { raw: '', tokens: [] };
  const tokens = value
    .split(',')
    .map((token) => token.trim().toLowerCase())
    .filter((token) => token !== '');
  return { raw: value, tokens };
}

function inspectAcceptCh(headers) {
  const accept = tokensOf(headers, HEADER_ACCEPT);
  const critical = tokensOf(headers, HEADER_CRITICAL);
  if (!accept.raw && !critical.raw) {
    return { changed: false, reason: REASON.MISSING, missing: [] };
  }
  if (accept.raw.length > MAX_FIELD_LENGTH || critical.raw.length > MAX_FIELD_LENGTH) {
    return { changed: true, reason: REASON.OVERLONG, missing: [] };
  }
  if (accept.tokens.length > MAX_HINTS || critical.tokens.length > MAX_HINTS) {
    return { changed: true, reason: REASON.TOO_MANY, missing: [] };
  }
  for (const token of accept.tokens) {
    if (!HINT_TOKEN.test(token) || token.length > MAX_HINT_LENGTH) {
      return { changed: true, reason: REASON.MALFORMED, missing: [] };
    }
  }
  for (const token of critical.tokens) {
    if (!HINT_TOKEN.test(token)) {
      return { changed: true, reason: REASON.MALFORMED, missing: [] };
    }
  }
  if (critical.tokens.length > 0 && accept.tokens.length === 0) {
    return { changed: true, reason: REASON.CRITICAL_EMPTY, missing: [] };
  }
  const missing = critical.tokens.filter((token) => !accept.tokens.includes(token));
  if (missing.length > 0) {
    return { changed: true, reason: REASON.CRITICAL_UNKNOWN, missing };
  }
  return { changed: false, reason: REASON.OK, missing: [] };
}

function applyAcceptChGuard(headers) {
  const result = inspectAcceptCh(headers);
  if (!result.changed) return result;
  const criticalKey = headerKey(headers, HEADER_CRITICAL);
  if (criticalKey) delete headers[criticalKey];
  return result;
}

function describeReason(reason) {
  switch (reason) {
    case REASON.MALFORMED:
      return 'Accept-CH 或 Critical-CH 含非法提示词';
    case REASON.TOO_MANY:
      return '客户端提示数量超过上限';
    case REASON.CRITICAL_UNKNOWN:
      return 'Critical-CH 声明了未在 Accept-CH 出现的提示';
    case REASON.CRITICAL_EMPTY:
      return 'Critical-CH 存在但 Accept-CH 为空';
    case REASON.OVERLONG:
      return '客户端提示字段超长';
    default:
      return '客户端提示协商一致';
  }
}

module.exports = {
  REASON,
  HEADER_ACCEPT,
  HEADER_CRITICAL,
  MAX_HINTS,
  MAX_HINT_LENGTH,
  MAX_FIELD_LENGTH,
  headerKey,
  tokensOf,
  inspectAcceptCh,
  applyAcceptChGuard,
  describeReason,
};
