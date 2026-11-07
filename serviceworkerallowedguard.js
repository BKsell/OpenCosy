'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  TRAVERSAL: 'path-traversal',
  OUTSIDE_ORIGIN: 'outside-origin',
  TOO_LONG: 'too-long',
};

const MAX_VALUE_LENGTH = 256;

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

function describeReason(reason) {
  switch (reason) {
    case REASON.TRAVERSAL:
      return 'Service-Worker-Allowed 含上级目录引用';
    case REASON.OUTSIDE_ORIGIN:
      return 'Service-Worker-Allowed 不是同源绝对路径';
    case REASON.MALFORMED:
      return 'Service-Worker-Allowed 取值为空';
    case REASON.TOO_LONG:
      return 'Service-Worker-Allowed 取值超长';
    case REASON.MISSING:
      return '响应未声明服务工作线程作用域';
    default:
      return '服务工作线程作用域合法';
  }
}

module.exports = {
  REASON,
  MAX_VALUE_LENGTH,
  scopePath,
  scopeCovers,
  inspectServiceWorkerAllowed,
  applyServiceWorkerAllowedGuard,
  describeReason,
};
