'use strict';

const REASON = {
  OK: 'ok',
  UPGRADED: 'upgraded-to-https',
  BLOCKED: 'insecure-blocked',
  LOCAL_OK: 'loopback-allowed',
  INVALID: 'invalid-url',
  HSTS: 'hsts-required',
};

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);

function parse(value) {
  if (typeof value !== 'string' || !value) return null;
  try {
    return new URL(value);
  } catch (err) {
    return null;
  }
}

function isLocal(host) {
  const h = String(host || '').toLowerCase();
  return LOCAL_HOSTS.has(h) || h.endsWith('.localhost');
}

function upgrade(urlValue) {
  const url = parse(urlValue);
  if (!url) return { url: '', changed: false, reason: REASON.INVALID };
  if (url.protocol === 'https:') return { url: url.href, changed: false, reason: REASON.OK };
  if (url.protocol !== 'http:') return { url: url.href, changed: false, reason: REASON.OK };
  if (isLocal(url.hostname)) {
    return { url: url.href, changed: false, reason: REASON.LOCAL_OK };
  }
  const secure = new URL(url.href);
  secure.protocol = 'https:';
  if (url.port === '80') secure.port = '';
  return { url: secure.href, changed: true, reason: REASON.UPGRADED };
}

function evaluate(request) {
  const req = request && typeof request === 'object' ? request : {};
  const result = upgrade(req.url);
  if (result.reason === REASON.UPGRADED && !req.allowUpgrade) {
    return { blocked: true, url: req.url, reason: REASON.BLOCKED, upgradeTo: result.url };
  }
  return { blocked: false, url: result.url, reason: result.reason, upgradeTo: result.changed ? result.url : '' };
}

function applyUpgradeInsecureGuard(request) {
  const req = request && typeof request === 'object' ? request : {};
  const result = evaluate(req);
  const headers = Object.assign({}, req.headers || {});
  const hsts = req.hsts || 'max-age=31536000; includeSubDomains';
  const parsed = parse(req.url);
  if (parsed && parsed.protocol === 'https:') headers['Strict-Transport-Security'] = hsts;
  return {
    blocked: result.blocked,
    url: result.url,
    reason: result.reason,
    upgradeTo: result.upgradeTo,
    headers,
  };
}

function auditInsecureBatch(requests, options) {
  const list = Array.isArray(requests) ? requests : [];
  const findings = [];
  let upgraded = 0;
  let blocked = 0;
  for (const item of list) {
    const result = evaluate(item);
    if (result.reason === REASON.UPGRADED) upgraded += 1;
    if (result.blocked) blocked += 1;
    if (result.reason !== REASON.OK) findings.push({ url: item && item.url, reason: result.reason });
  }
  const limit = Number(options && options.maxFindings) || 10;
  return { upgraded, blocked, total: list.length, findings: findings.slice(0, limit) };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no insecure transport risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applyUpgradeInsecureGuard,
  auditInsecureBatch,
  describeFindings,
  upgrade,
};
