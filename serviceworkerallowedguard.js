'use strict';
const { describeReasonTable } = require('./reasontext');

const { headerKey, headerText } = require('./headerutil');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  TRAVERSAL: 'path-traversal',
  OUTSIDE_ORIGIN: 'outside-origin',
  TOO_LONG: 'too-long',
};

const MAX_VALUE_LENGTH = 256;

function scopePath(value) {
  const text = String(value || '').trim();
  if (!text.startsWith('/')) return '';
  if (text.length > MAX_VALUE_LENGTH) return '';
  if (text.includes('..')) return '';
  if (/[\\\u0000-\u001f\u007f]/.test(text)) return '';
  return text;
}

function inspectServiceWorkerAllowed(headers) {
  const key = headerKey(headers, 'service-worker-allowed');
  if (!key) return { changed: false, reason: REASON.MISSING, scope: '' };
  const text = headerText(headers, 'service-worker-allowed').trim();
  if (!text) return { changed: true, reason: REASON.MALFORMED, scope: '' };
  if (text.length > MAX_VALUE_LENGTH) {
    return { changed: true, reason: REASON.TOO_LONG, scope: '' };
  }
  if (text.includes('..')) {
    return { changed: true, reason: REASON.TRAVERSAL, scope: '' };
  }
  const scope = scopePath(text);
  if (!scope) {
    return { changed: true, reason: REASON.OUTSIDE_ORIGIN, scope: '' };
  }
  return { changed: false, reason: REASON.OK, scope };
}

function applyServiceWorkerAllowedGuard(headers) {
  const result = inspectServiceWorkerAllowed(headers);
  if (!result.changed) return result;
  const key = headerKey(headers, 'service-worker-allowed');
  if (key) delete headers[key];
  return result;
}

function scopeCovers(scope, scriptPath) {
  const normalized = String(scriptPath || '').trim();
  if (!scope || !normalized) return false;
  if (!scope.startsWith('/')) return false;
  if (scope.endsWith('/')) return normalized.startsWith(scope);
  const prefix = scope + '/';
  return normalized === scope || normalized.startsWith(prefix);
}

const describeReason = describeReasonTable({
    [REASON.TRAVERSAL]: 'Service-Worker-Allowed 含上级目录引用',
    [REASON.OUTSIDE_ORIGIN]: 'Service-Worker-Allowed 不是同源绝对路径',
    [REASON.MALFORMED]: 'Service-Worker-Allowed 取值为空',
    [REASON.TOO_LONG]: 'Service-Worker-Allowed 取值超长',
    [REASON.MISSING]: '响应未声明服务工作线程作用域',
  }, '服务工作线程作用域合法');

module.exports = {
  REASON,
  MAX_VALUE_LENGTH,
  scopePath,
  scopeCovers,
  inspectServiceWorkerAllowed,
  applyServiceWorkerAllowedGuard,
  describeReason,
};
