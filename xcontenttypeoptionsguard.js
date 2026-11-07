'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  INVALID: 'invalid-value',
  DUPLICATE: 'duplicate-header',
  OVERLONG: 'overlong-value',
  DOWNGRADED: 'normalized',
};

const REQUIRED_VALUE = 'nosniff';
const MAX_VALUE_LENGTH = 64;

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function inspectXContentTypeOptions(headers) {
  const key = headerKey(headers, 'x-content-type-options');
  if (!key) return { present: false, key: '', reason: REASON.MISSING };
  const raw = headers[key];
  const list = Array.isArray(raw) ? raw : [raw];
  const tokens = list
    .map((item) => (typeof item === 'string' ? item.trim().toLowerCase() : ''))
    .filter((item) => item.length > 0);
  if (!tokens.length) return { present: true, key, reason: REASON.INVALID };
  if (tokens.some((token) => token.length > MAX_VALUE_LENGTH)) {
    return { present: true, key, reason: REASON.OVERLONG };
  }
  if (tokens.length > 1) return { present: true, key, reason: REASON.DUPLICATE };
  if (tokens[0] !== REQUIRED_VALUE) return { present: true, key, reason: REASON.INVALID };
  return { present: true, key, reason: REASON.OK };
}

function applyXContentTypeOptionsGuard(headers) {
  const result = inspectXContentTypeOptions(headers);
  if (!result.present) {
    headers['X-Content-Type-Options'] = REQUIRED_VALUE;
    return { changed: true, reason: REASON.MISSING, value: REQUIRED_VALUE };
  }
  if (result.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, value: REQUIRED_VALUE };
  }
  headers[result.key] = REQUIRED_VALUE;
  return { changed: true, reason: result.reason, value: REQUIRED_VALUE };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.MISSING:
      return '缺少 X-Content-Type-Options，已补 nosniff';
    case REASON.INVALID:
      return 'X-Content-Type-Options 取值非法，已改为 nosniff';
    case REASON.DUPLICATE:
      return 'X-Content-Type-Options 重复，已合并';
    case REASON.OVERLONG:
      return 'X-Content-Type-Options 超长，已改为 nosniff';
    case REASON.DOWNGRADED:
      return 'X-Content-Type-Options 已规范化';
    default:
      return 'X-Content-Type-Options 通过校验';
  }
}

module.exports = {
  REASON,
  REQUIRED_VALUE,
  MAX_VALUE_LENGTH,
  inspectXContentTypeOptions,
  applyXContentTypeOptionsGuard,
  describeReason,
};
