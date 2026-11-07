'use strict';

const REASON = {
  OK: 'ok',
  INVALID: 'invalid-url',
  SCHEME_BLOCKED: 'scheme-blocked',
  DOWNGRADE: 'https-downgrade',
  HTTP_PLAINTEXT: 'http-plaintext',
  CREDENTIALS: 'url-credentials',
  HOMELESS: 'opaque-origin',
};

const SAFE_SCHEMES = new Set(['https:', 'wss:', 'http:', 'ws:', 'file:', 'chrome:', 'about:', 'devtools:']);

function parse(value) {
  if (typeof value !== 'string' || value.length === 0) return null;
  if (value.length > 8192) return null;
  try {
    return new URL(value);
  } catch (err) {
    return null;
  }
}

function isLoopbackHost(host) {
  if (host === 'localhost' || host === '127.0.0.1' || host === '[::1]') return true;
  if (host.endsWith('.localhost')) return true;
  return false;
}

function hasCredentials(url) {
  return Boolean(url.username) || Boolean(url.password);
}

function normalizeHost(host) {
  return String(host || '').toLowerCase().replace(/^www\./, '');
}

function isSameSite(a, b) {
  const left = normalizeHost(a);
  const right = normalizeHost(b);
  if (left === right) return true;
  const leftParts = left.split('.');
  const rightParts = right.split('.');
  if (leftParts.length < 2 || rightParts.length < 2) return false;
  return leftParts.slice(-2).join('.') === rightParts.slice(-2).join('.');
}

function tripleKey(host) {
  return normalizeHost(host).split('.').slice(-3).join('.');
}

function evaluate(fromUrl, toUrl, options) {
  const opts = options && typeof options === 'object' ? options : {};
  const from = parse(fromUrl);
  const to = parse(toUrl);
  if (!to) {
    return { blocked: true, changed: false, reason: REASON.INVALID, url: '' };
  }
  if (!SAFE_SCHEMES.has(to.protocol)) {
    return { blocked: true, changed: false, reason: REASON.SCHEME_BLOCKED, url: to.href };
  }
  if (to.protocol === 'about:' || to.protocol === 'chrome:' || to.protocol === 'devtools:') {
    return { blocked: false, changed: false, reason: REASON.HOMELESS, url: to.href };
  }
  if (hasCredentials(to)) {
    const clean = new URL(to.href);
    clean.username = '';
    clean.password = '';
    return { blocked: true, changed: true, reason: REASON.CREDENTIALS, url: clean.href };
  }
  if (isLoopbackHost(to.hostname) && (to.protocol === 'http:' || to.protocol === 'ws:')) {
    return { blocked: false, changed: false, reason: REASON.HTTP_PLAINTEXT, url: to.href };
  }
  if (from && from.protocol === 'https:' && to.protocol === 'http:') {
    return { blocked: true, changed: false, reason: REASON.DOWNGRADE, url: to.href, from: from.href };
  }
  if (from && from.protocol === 'wss:' && to.protocol === 'ws:') {
    return { blocked: true, changed: false, reason: REASON.DOWNGRADE, url: to.href, from: from.href };
  }
  if (to.protocol === 'http:' || to.protocol === 'ws:') {
    if (opts.allowPlaintextForSameTriple && from && tripleKey(from.hostname) === tripleKey(to.hostname)) {
      return { blocked: false, changed: false, reason: REASON.HTTP_PLAINTEXT, url: to.href };
    }
    if (opts.strict) {
      const upgraded = new URL(to.href);
      upgraded.protocol = to.protocol === 'ws:' ? 'wss:' : 'https:';
      return { blocked: false, changed: true, reason: REASON.HTTP_PLAINTEXT, url: upgraded.href };
    }
    return { blocked: true, changed: false, reason: REASON.HTTP_PLAINTEXT, url: to.href };
  }
  return { blocked: false, changed: false, reason: REASON.OK, url: to.href };
}

function applyNavigationDowngradeGuard(request) {
  const req = request && typeof request === 'object' ? request : {};
  const result = evaluate(req.from, req.to, req.options || {});
  return {
    blocked: result.blocked,
    changed: result.changed,
    reason: result.reason,
    url: result.url,
    redirectTo: result.url,
  };
}

function auditNavigationBatch(requests, options) {
  const list = Array.isArray(requests) ? requests : [];
  const findings = [];
  let blocked = 0;
  let rewritten = 0;
  for (const item of list) {
    const result = evaluate(item && item.from, item && item.to, options || {});
    if (result.blocked) blocked += 1;
    if (result.changed) rewritten += 1;
    if (result.blocked || result.changed) {
      findings.push({ from: item && item.from, to: item && item.to, reason: result.reason, url: result.url });
    }
  }
  return { blocked, rewritten, findings, total: list.length };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no navigation risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.url || f.to || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  applyNavigationDowngradeGuard,
  auditNavigationBatch,
  describeFindings,
  isSameSite,
  tripleKey,
};
