'use strict';
const { parseUrl } = require('./modutil_core');
const { describeReasonTable } = require('./reasontext');

const REASON = {
  OK: 'ok',
  INVALID: 'invalid-url',
  SAME_ORIGIN: 'same-origin',
  CROSS_ORIGIN: 'cross-origin',
  DOWNGRADE: 'https-downgrade',
  LOOP: 'redirect-loop',
  UPGRADE: 'scheme-upgrade',
};

const CREDENTIAL_HEADERS = ['authorization', 'cookie', 'proxy-authorization'];

function headerKeys(headers, name) {
  const lower = name.toLowerCase();
  const keys = [];
  if (!headers || typeof headers !== 'object') return keys;
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) keys.push(key);
  }
  return keys;
}

function stripCredentials(headers) {
  const stripped = [];
  for (const name of CREDENTIAL_HEADERS) {
    for (const key of headerKeys(headers, name)) {
      delete headers[key];
      stripped.push(name);
    }
  }
  return stripped;
}

function evaluateRedirect(redirect) {
  if (!redirect || typeof redirect !== 'object') return { allowed: false, reason: REASON.INVALID, stripped: [] };
  const from = parseUrl(redirect.from);
  const to = parseUrl(redirect.to);
  if (!from || !to) return { allowed: false, reason: REASON.INVALID, stripped: [] };
  const fromOrigin = from.origin;
  const toOrigin = to.origin;
  if (fromOrigin === toOrigin) return { allowed: true, reason: REASON.SAME_ORIGIN, headers: redirect.headers || {}, stripped: [] };
  if (from.protocol === 'https:' && to.protocol === 'http:') {
    return { allowed: false, reason: REASON.DOWNGRADE, headers: redirect.headers || {}, stripped: [] };
  }
  const headers = redirect.headers || {};
  const stripped = stripCredentials(headers);
  if (from.hostname === to.hostname && from.port === to.port) {
    return { allowed: true, reason: REASON.UPGRADE, headers, stripped };
  }
  return { allowed: true, reason: REASON.CROSS_ORIGIN, headers, stripped };
}

function applyRedirectCredentialGuard(redirect) {
  if (!redirect || typeof redirect !== 'object') return { changed: true, reason: REASON.INVALID, stripped: [] };
  const result = evaluateRedirect(redirect);
  const changed = !result.allowed || result.stripped.length > 0;
  return { changed, reason: result.reason, headers: result.headers, stripped: result.stripped };
}

const describeReason = describeReasonTable({
    [REASON.INVALID]: '重定向地址无法解析',
    [REASON.CROSS_ORIGIN]: '跨源重定向已剥离凭据头',
    [REASON.DOWNGRADE]: '重定向发生 HTTPS 降级',
    [REASON.LOOP]: '重定向形成循环',
    [REASON.UPGRADE]: '重定向升级为 HTTPS 并剥离凭据头',
  }, '重定向保持同源');

module.exports = {
  REASON,
  CREDENTIAL_HEADERS,
  parseUrl,
  evaluateRedirect,
  applyRedirectCredentialGuard,
  describeReason,
};
