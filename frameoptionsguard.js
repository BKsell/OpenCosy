'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  ALLOW_FROM: 'allow-from-deprecated',
  ALLOW_ALL: 'allow-all',
  MULTIPLE_VALUES: 'multiple-values',
  CSP_CONFLICT: 'csp-conflict',
};

const VALID_TOKENS = new Set(['deny', 'sameorigin']);

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function headerText(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return '';
  const raw = headers[key];
  const value = Array.isArray(raw) ? raw.join(', ') : raw;
  return typeof value === 'string' ? value : '';
}

function cspDeclaresFrameAncestors(headers) {
  const csp = headerText(headers, 'content-security-policy');
  if (!csp) return false;
  return csp
    .split(';')
    .map((part) => part.trim().toLowerCase())
    .some((part) => part.startsWith('frame-ancestors'));
}

function inspectFrameOptions(headers) {
  const key = headerKey(headers, 'x-frame-options');
  if (!key) return { changed: false, reason: REASON.MISSING, value: '' };
  const text = headerText(headers, 'x-frame-options');
  const trimmed = text.trim();
  if (!trimmed) {
    return { changed: true, reason: REASON.MALFORMED, value: text };
  }
  if (cspDeclaresFrameAncestors(headers)) {
    return { changed: true, reason: REASON.CSP_CONFLICT, value: text };
  }
  const raw = Array.isArray(headers[key]) ? headers[key] : [text];
  const segments = raw
    .flatMap((item) => String(item).split(','))
    .map((item) => item.trim())
    .filter(Boolean);
  if (segments.length > 1) {
    return { changed: true, reason: REASON.MULTIPLE_VALUES, value: text };
  }
  const token = (segments[0] || '').toLowerCase();
  if (token.startsWith('allow-from')) {
    return { changed: true, reason: REASON.ALLOW_FROM, value: text };
  }
  if (token === 'allowall' || token === 'allow-all' || token === '*') {
    return { changed: true, reason: REASON.ALLOW_ALL, value: text };
  }
  if (!VALID_TOKENS.has(token)) {
    return { changed: true, reason: REASON.MALFORMED, value: text };
  }
  if (!Array.isArray(headers[key])) {
    headers[key] = segments[0];
  }
  return { changed: false, reason: REASON.OK, value: segments[0] };
}

function applyFrameOptionsGuard(headers) {
  const result = inspectFrameOptions(headers);
  if (!result.changed) return result;
  const key = headerKey(headers, 'x-frame-options');
  if (key) delete headers[key];
  return result;
}

function describeReason(reason) {
  switch (reason) {
    case REASON.ALLOW_FROM:
      return 'ALLOW-FROM 已被现代内核忽略，站点误以为仍受保护';
    case REASON.ALLOW_ALL:
      return '站点显式允许任意来源嵌入';
    case REASON.MULTIPLE_VALUES:
      return '响应声明了多个 X-Frame-Options 取值';
    case REASON.CSP_CONFLICT:
      return 'X-Frame-Options 与 CSP frame-ancestors 冲突';
    case REASON.MALFORMED:
      return 'X-Frame-Options 取值非法';
    case REASON.MISSING:
      return '站点未声明 X-Frame-Options';
    default:
      return 'X-Frame-Options 有效';
  }
}

module.exports = {
  REASON,
  VALID_TOKENS,
  inspectFrameOptions,
  applyFrameOptionsGuard,
  cspDeclaresFrameAncestors,
  describeReason,
};
