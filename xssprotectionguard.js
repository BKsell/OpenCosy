'use strict';
const { describeReasonTable } = require('./reasontext');
const { applySingleHeaderGuard } = require('./guardapply');

const { headerKey } = require('./headerutil');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  LEGACY_ENABLED: 'legacy-enabled',
  LEGACY_DISABLED: 'legacy-disabled',
  MALFORMED: 'malformed',
};

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
  return applySingleHeaderGuard(headers, 'x-xss-protection', inspectXSSProtection);
}

const describeReason = describeReasonTable({
    [REASON.LEGACY_ENABLED]: '旧版 XSS 过滤器会引入新的旁路风险',
    [REASON.LEGACY_DISABLED]: '站点显式关闭旧版 XSS 过滤器',
    [REASON.MALFORMED]: 'X-XSS-Protection 取值非法',
    [REASON.MISSING]: '响应未声明旧版 XSS 过滤器',
  }, '旧版 XSS 过滤器已清理');

module.exports = {
  REASON,
  inspectXSSProtection,
  applyXSSProtectionGuard,
  describeReason,
};
