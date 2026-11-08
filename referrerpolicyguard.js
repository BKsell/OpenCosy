'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  UNSAFE: 'unsafe-url',
  UNKNOWN_TOKEN: 'unknown-token',
  TOO_MANY: 'too-many-values',
};

const SAFE_POLICIES = new Set([
  'no-referrer',
  'no-referrer-when-downgrade',
  'origin',
  'origin-when-cross-origin',
  'same-origin',
  'strict-origin',
  'strict-origin-when-cross-origin',
]);

const FALLBACK_POLICY = 'strict-origin-when-cross-origin';
const MAX_VALUE_LENGTH = 256;
const MAX_TOKENS = 4;

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function rawValue(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return null;
  const raw = headers[key];
  return Array.isArray(raw) ? raw : [raw];
}

function normalizeToken(token) {
  return typeof token === 'string' ? token.trim().toLowerCase() : '';
}

function parseReferrerPolicy(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED };
  const text = value.trim();
  if (!text) return { reason: REASON.MISSING };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG };
  const parts = text.split(',');
  if (parts.length > MAX_TOKENS) return { reason: REASON.TOO_MANY };
  const tokens = [];
  let unsafe = false;
  let unknown = false;
  for (const part of parts) {
    const token = normalizeToken(part);
    if (!token) continue;
    if (token === 'unsafe-url') {
      unsafe = true;
      continue;
    }
    if (!SAFE_POLICIES.has(token)) {
      unknown = true;
      continue;
    }
    if (!tokens.includes(token)) tokens.push(token);
  }
  if (unsafe) {
    if (!tokens.length) tokens.push(FALLBACK_POLICY);
    return { reason: REASON.UNSAFE, tokens, value: tokens.join(', ') };
  }
  if (!tokens.length) {
    return { reason: unknown ? REASON.UNKNOWN_TOKEN : REASON.MALFORMED, tokens: [], value: '' };
  }
  return {
    reason: unknown ? REASON.UNKNOWN_TOKEN : REASON.OK,
    tokens,
    value: tokens.join(', '),
  };
}

function applyReferrerPolicyGuard(headers) {
  const values = rawValue(headers, 'referrer-policy');
  if (!values) return { changed: false, reason: REASON.MISSING, value: '' };
  const key = headerKey(headers, 'referrer-policy');
  const first = typeof values[0] === 'string' ? values[0] : '';
  const parsed = parseReferrerPolicy(first);
  const requiresRewrite = parsed.reason === REASON.UNSAFE ||
    parsed.reason === REASON.UNKNOWN_TOKEN ||
    parsed.reason === REASON.MALFORMED ||
    parsed.reason === REASON.OVERLONG ||
    parsed.reason === REASON.TOO_MANY ||
    values.length > 1;

  if (!requiresRewrite) {
    return { changed: false, reason: parsed.reason, value: parsed.value };
  }
  if (parsed.reason === REASON.UNSAFE) {
    const safe = parsed.value || FALLBACK_POLICY;
    headers[key] = safe;
    return { changed: true, reason: REASON.UNSAFE, value: safe };
  }
  if (parsed.reason === REASON.UNKNOWN_TOKEN && parsed.tokens.length) {
    const safe = parsed.value;
    headers[key] = safe;
    return { changed: true, reason: REASON.UNKNOWN_TOKEN, value: safe };
  }
  headers[key] = FALLBACK_POLICY;
  return { changed: true, reason: parsed.reason, value: FALLBACK_POLICY };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.MISSING:
      return '未声明 Referrer-Policy';
    case REASON.MALFORMED:
      return 'Referrer-Policy 无法解析，回退到严格策略';
    case REASON.OVERLONG:
      return 'Referrer-Policy 超长，回退到严格策略';
    case REASON.UNSAFE:
      return 'Referrer-Policy 使用 unsafe-url，已收紧';
    case REASON.UNKNOWN_TOKEN:
      return 'Referrer-Policy 含未知取值，已剔除';
    case REASON.TOO_MANY:
      return 'Referrer-Policy 取值过多，回退到严格策略';
    default:
      return 'Referrer-Policy 通过校验';
  }
}

module.exports = {
  REASON,
  SAFE_POLICIES,
  FALLBACK_POLICY,
  MAX_VALUE_LENGTH,
  parseReferrerPolicy,
  applyReferrerPolicyGuard,
  describeReason,
};
