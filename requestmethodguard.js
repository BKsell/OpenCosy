'use strict';

const REASON = Object.freeze({
  OK: 'ok',
  UNSAFE_METHOD: 'unsafe-method',
  UNKNOWN_METHOD: 'unknown-method',
  CONTROL_CHAR: 'control-char',
  URL_USERINFO: 'url-userinfo',
  BLOCKED_SCHEME: 'blocked-scheme',
  DATA_NAVIGATION: 'data-navigation',
});

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE']);
const UNSAFE_METHODS = new Set(['TRACE', 'TRACK', 'CONNECT']);
const BLOCKED_SCHEMES = new Set(['ftp:', 'gopher:', 'ws:', 'wss:', 'file:']);
const TOKEN = /^[A-Z][A-Z0-9_-]*$/;

function isHttpUrl(url) {
  return typeof url === 'string' && (url.startsWith('http://') || url.startsWith('https://'));
}

function hasUserinfo(url) {
  if (typeof url !== 'string') return false;
  const head = url.split('#')[0];
  const schemeEnd = head.indexOf('://');
  if (schemeEnd < 0) return false;
  const authorityEnd = head.indexOf('/', schemeEnd + 3);
  const authority = authorityEnd < 0 ? head.slice(schemeEnd + 3) : head.slice(schemeEnd + 3, authorityEnd);
  return authority.includes('@');
}

function schemeOf(url) {
  if (typeof url !== 'string') return '';
  const idx = url.indexOf(':');
  if (idx <= 0) return '';
  return url.slice(0, idx + 1).toLowerCase();
}

function evaluateRequestMethod(input = {}) {
  const url = typeof input.url === 'string' ? input.url : '';
  const method = String(input.method || 'GET').toUpperCase();

  if (/[\u0000-\u001f\u007f]/.test(url)) {
    return { action: 'cancel', reason: REASON.CONTROL_CHAR, detail: '请求 URL 含控制字符' };
  }
  if (!TOKEN.test(method)) {
    return { action: 'cancel', reason: REASON.UNKNOWN_METHOD, detail: '请求方法不是合法 token' };
  }
  if (UNSAFE_METHODS.has(method)) {
    return { action: 'cancel', reason: REASON.UNSAFE_METHOD, detail: `禁止 ${method} 请求` };
  }
  if (!SAFE_METHODS.has(method)) {
    return { action: 'cancel', reason: REASON.UNKNOWN_METHOD, detail: `非常规方法 ${method}` };
  }
  if (hasUserinfo(url)) {
    return { action: 'cancel', reason: REASON.URL_USERINFO, detail: 'URL 内嵌账号口令' };
  }
  const scheme = schemeOf(url);
  if (input.resourceType === 'mainFrame' && scheme === 'data:') {
    return { action: 'cancel', reason: REASON.DATA_NAVIGATION, detail: '顶层导航不得使用 data: 协议' };
  }
  if (!isHttpUrl(url) && BLOCKED_SCHEMES.has(scheme)) {
    return { action: 'cancel', reason: REASON.BLOCKED_SCHEME, detail: `禁止子资源使用 ${scheme} 协议` };
  }
  return { action: 'allow', reason: REASON.OK, detail: '' };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK: return '请求方法合法';
    case REASON.UNSAFE_METHOD: return '危险 HTTP 方法';
    case REASON.UNKNOWN_METHOD: return '非常规请求方法';
    case REASON.CONTROL_CHAR: return '请求 URL 含控制字符';
    case REASON.URL_USERINFO: return 'URL 内嵌凭据';
    case REASON.BLOCKED_SCHEME: return '协议被请求守卫禁用';
    case REASON.DATA_NAVIGATION: return 'data: 顶层导航';
    default: return '未知原因';
  }
}

module.exports = {
  REASON,
  SAFE_METHODS,
  UNSAFE_METHODS,
  evaluateRequestMethod,
  describeReason,
};
