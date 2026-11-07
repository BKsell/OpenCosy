'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  LEGACY_ENABLED: 'legacy-enabled',
  LEGACY_DISABLED: 'legacy-disabled',
  MALFORMED: 'malformed',
};

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

function inspectXSSProtection(headers) {
  const key = headerKey(headers, 'x-xss-protection');
  if (!key) return { changed: false, reason: REASON.MISSING, value: '' };
  const text = headerText(headers, 'x-xss-protection').trim();
  if (!text) return { changed: true, reason: REASON.MALFORMED, value: '' };
  const token = text.split(';')[0].trim().toLowerCase();
  if (token === '0') return { changed: true, reason: REASON.LEGACY_DISABLED, value: text };
  if (token === '1') return { changed: true, reason: REASON.LEGACY_ENABLED, value: text };
  return { changed: true, reason: REASON.MALFORMED, value: text };
}

function applyXSSProtectionGuard(headers) {
  const result = inspectXSSProtection(headers);
  if (!result.changed) return result;
  const key = headerKey(headers, 'x-xss-protection');
  if (key) delete headers[key];
  return result;
}

function describeReason(reason) {
  switch (reason) {
    case REASON.LEGACY_ENABLED:
      return '旧版 XSS 过滤器会引入新的旁路风险';
    case REASON.LEGACY_DISABLED:
      return '站点显式关闭旧版 XSS 过滤器';
    case REASON.MALFORMED:
      return 'X-XSS-Protection 取值非法';
    case REASON.MISSING:
      return '响应未声明旧版 XSS 过滤器';
    default:
      return '旧版 XSS 过滤器已清理';
  }
}

module.exports = {
  REASON,
  inspectXSSProtection,
  applyXSSProtectionGuard,
  describeReason,
};
