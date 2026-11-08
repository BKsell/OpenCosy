'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed-origin',
  WILDCARD_CREDENTIALED: 'wildcard-with-credentials',
  TOO_MANY: 'too-many-origins',
  OVERLONG: 'overlong-value',
};

const MAX_VALUE_LENGTH = 512;
const MAX_ORIGINS = 8;
const ORIGIN = /^https?:\/\/[a-z0-9.-]+(:\d{1,5})?$/i;

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function credentialsEnabled(headers) {
  const key = headerKey(headers, 'access-control-allow-credentials');
  if (!key) return false;
  const raw = headers[key];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === 'string' && value.trim().toLowerCase() === 'true';
}

function parseTimingAllowOrigin(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED };
  const text = value.trim();
  if (!text) return { reason: REASON.MISSING };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG };
  const parts = text.split(',');
  if (parts.length > MAX_ORIGINS) return { reason: REASON.TOO_MANY };
  const origins = [];
  let wildcard = false;
  for (const part of parts) {
    const token = part.trim();
    if (!token) continue;
    if (token === '*') {
      wildcard = true;
      continue;
    }
    const normalized = token.toLowerCase().replace(/\/$/, '');
    if (!ORIGIN.test(normalized)) return { reason: REASON.MALFORMED };
    if (!origins.includes(normalized)) origins.push(normalized);
  }
  if (wildcard) return { reason: REASON.OK, wildcard: true, origins: [] };
  if (!origins.length) return { reason: REASON.MALFORMED };
  return { reason: REASON.OK, wildcard: false, origins };
}

function inspectTimingAllowOrigin(headers) {
  const key = headerKey(headers, 'timing-allow-origin');
  if (!key) return { present: false, key: '', reason: REASON.MISSING };
  const raw = headers[key];
  const value = Array.isArray(raw) ? raw[0] : raw;
  const parsed = parseTimingAllowOrigin(value);
  if (parsed.reason !== REASON.OK) {
    return { present: true, key, reason: parsed.reason, parsed };
  }
  if (parsed.wildcard && credentialsEnabled(headers)) {
    return { present: true, key, reason: REASON.WILDCARD_CREDENTIALED, parsed };
  }
  return { present: true, key, reason: REASON.OK, parsed };
}

function applyTimingAllowOriginGuard(headers) {
  const result = inspectTimingAllowOrigin(headers);
  if (!result.present) return { changed: false, reason: REASON.MISSING, value: '' };
  if (result.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, value: headers[result.key] };
  }
  if (result.reason === REASON.WILDCARD_CREDENTIALED) {
    delete headers[result.key];
    return { changed: true, reason: REASON.WILDCARD_CREDENTIALED, value: '' };
  }
  delete headers[result.key];
  return { changed: true, reason: result.reason, value: '' };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.MISSING:
      return '未声明 Timing-Allow-Origin';
    case REASON.MALFORMED:
      return 'Timing-Allow-Origin 源格式非法，已移除';
    case REASON.WILDCARD_CREDENTIALED:
      return '带凭据响应使用通配 TAO，已移除';
    case REASON.TOO_MANY:
      return 'Timing-Allow-Origin 条目过多，已移除';
    case REASON.OVERLONG:
      return 'Timing-Allow-Origin 超长，已移除';
    default:
      return 'Timing-Allow-Origin 通过校验';
  }
}

module.exports = {
  REASON,
  MAX_VALUE_LENGTH,
  MAX_ORIGINS,
  parseTimingAllowOrigin,
  inspectTimingAllowOrigin,
  applyTimingAllowOriginGuard,
  describeReason,
};
