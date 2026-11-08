'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  BROAD_POLICY: 'broad-policy',
  MULTI_VALUE: 'multi-value',
};

const HEADER = 'x-permitted-cross-domain-policies';
const STRICT = 'none';
const MAX_VALUE_LENGTH = 96;
const BROAD = new Set(['all', 'master-only', 'by-content-type', 'by-ftp-filename']);

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

function countValues(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return 0;
  const raw = headers[key];
  if (Array.isArray(raw)) return raw.length;
  return typeof raw === 'string' ? 1 : 0;
}

function parseCrossDomainPolicy(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, policy: null };
  const text = value.trim().toLowerCase();
  if (!text) return { reason: REASON.MALFORMED, policy: null };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG, policy: null };
  if (text === STRICT) return { reason: REASON.OK, policy: STRICT };
  if (BROAD.has(text)) return { reason: REASON.BROAD_POLICY, policy: text };
  const tokens = text.split(',').map((token) => token.trim()).filter((token) => token !== '');
  if (tokens.length === 0) return { reason: REASON.MALFORMED, policy: null };
  if (tokens.includes('all')) return { reason: REASON.BROAD_POLICY, policy: 'all' };
  for (const token of tokens) {
    if (BROAD.has(token)) return { reason: REASON.BROAD_POLICY, policy: token };
    if (token !== 'none') return { reason: REASON.MALFORMED, policy: null };
  }
  if (tokens.length > 1) return { reason: REASON.MULTI_VALUE, policy: null };
  return { reason: REASON.OK, policy: STRICT };
}

function inspectCrossDomainPolicy(headers) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING, policy: null };
  if (countValues(headers, HEADER) > 1) {
    return { changed: true, reason: REASON.MULTI_VALUE, policy: null };
  }
  const parsed = parseCrossDomainPolicy(value);
  if (parsed.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, policy: parsed.policy };
  }
  return { changed: true, reason: parsed.reason, policy: parsed.policy };
}

function applyCrossDomainPolicyGuard(headers) {
  const result = inspectCrossDomainPolicy(headers);
  if (!result.changed) return result;
  const key = headerKey(headers, HEADER);
  if (key) headers[key] = STRICT;
  return result;
}

function describeReason(reason) {
  switch (reason) {
    case REASON.MALFORMED:
      return 'X-Permitted-Cross-Domain-Policies 取值非法，已收紧为 none';
    case REASON.OVERLONG:
      return 'X-Permitted-Cross-Domain-Policies 字段超长，已收紧为 none';
    case REASON.BROAD_POLICY:
      return '跨域策略放宽了 flash 读取范围，已收紧为 none';
    case REASON.MULTI_VALUE:
      return 'X-Permitted-Cross-Domain-Policies 多头下发，已收敛为单值';
    case REASON.MISSING:
      return '响应未声明 X-Permitted-Cross-Domain-Policies';
    default:
      return '跨域策略为 none';
  }
}

module.exports = {
  REASON,
  HEADER,
  STRICT,
  MAX_VALUE_LENGTH,
  BROAD,
  headerKey,
  firstValue,
  countValues,
  parseCrossDomainPolicy,
  inspectCrossDomainPolicy,
  applyCrossDomainPolicyGuard,
  describeReason,
};
