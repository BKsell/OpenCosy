'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  DISABLED: 'disabled',
  MALFORMED: 'malformed',
  DUPLICATE: 'duplicate',
};

const MAX_VALUE_LENGTH = 256;
const MIN_ACCEPTABLE_MAX_AGE = 86400;

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

function parseHsts(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.MALFORMED };
  const directives = text.split(';').map((part) => part.trim()).filter(Boolean);
  const seen = new Set();
  let maxAge = null;
  for (const directive of directives) {
    const eq = directive.indexOf('=');
    const name = (eq < 0 ? directive : directive.slice(0, eq)).trim().toLowerCase();
    if (seen.has(name)) return { reason: REASON.DUPLICATE };
    seen.add(name);
    if (name === 'max-age') {
      if (eq < 0) return { reason: REASON.MALFORMED };
      const raw = directive.slice(eq + 1).trim().replace(/^"|"$/g, '');
      if (!/^\d{1,16}$/.test(raw)) return { reason: REASON.MALFORMED };
      maxAge = Number(raw);
    }
  }
  if (maxAge === null) return { reason: REASON.MALFORMED };
  if (maxAge === 0) return { reason: REASON.DISABLED, maxAge };
  if (maxAge < MIN_ACCEPTABLE_MAX_AGE) return { reason: REASON.DISABLED, maxAge };
  return { reason: REASON.OK, maxAge, includeSubDomains: seen.has('includesubdomains') };
}

function inspectHsts(headers) {
  const value = firstValue(headers, 'strict-transport-security');
  if (!value) return { changed: false, reason: REASON.MISSING, verdict: null };
  const parsed = parseHsts(value);
  if (parsed.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, verdict: parsed };
  }
  return { changed: true, reason: parsed.reason, verdict: parsed };
}

function applyHstsGuard(headers) {
  const result = inspectHsts(headers);
  if (!result.changed) return result;
  const key = headerKey(headers, 'strict-transport-security');
  if (key) delete headers[key];
  return result;
}

function describeReason(reason) {
  switch (reason) {
    case REASON.DISABLED:
      return '站点 HSTS 有效期过短或等于 0';
    case REASON.MALFORMED:
      return 'HSTS 头格式非法或缺 max-age';
    case REASON.DUPLICATE:
      return 'HSTS 头重复声明同一指令';
    case REASON.MISSING:
      return '站点未声明 HSTS';
    default:
      return 'HSTS 策略有效';
  }
}

module.exports = {
  REASON,
  MAX_VALUE_LENGTH,
  MIN_ACCEPTABLE_MAX_AGE,
  parseHsts,
  inspectHsts,
  applyHstsGuard,
  describeReason,
};
