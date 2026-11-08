'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'doh-endpoint-empty',
  INVALID: 'doh-endpoint-invalid',
  PLAINTEXT: 'doh-plaintext',
  CREDENTIALS: 'doh-credentials',
  HOST_NOT_ALLOWED: 'doh-host-not-allowed',
  LOOPBACK: 'doh-loopback',
  TEMPLATE_INVALID: 'doh-template-invalid',
  PARAM_UNSAFE: 'doh-param-unsafe',
};

const MAX_URL = 8192;
const MAX_PARAM = 63;

function evaluateDohEndpoint(endpoint, options) {
  const opts = options || {};
  if (typeof endpoint !== 'string' || endpoint.trim() === '') {
    return { ok: false, blocked: true, reason: REASON.EMPTY, url: '' };
  }
  if (endpoint.length > MAX_URL) {
    return { ok: false, blocked: true, reason: REASON.INVALID, url: endpoint.slice(0, 64) };
  }
  let url;
  try {
    url = new URL(endpoint.trim());
  } catch (err) {
    return { ok: false, blocked: true, reason: REASON.INVALID, url: endpoint.slice(0, 64) };
  }
  if (opts.allowPlaintext !== true && url.protocol !== 'https:') {
    const reason = url.protocol === 'http:' ? REASON.PLAINTEXT : REASON.INVALID;
    return { ok: false, blocked: true, reason, url: url.href };
  }
  if (url.username || url.password) {
    return { ok: false, blocked: true, reason: REASON.CREDENTIALS, url: url.href };
  }
  const host = url.hostname.toLowerCase();
  if (host === 'localhost' || host === '127.0.0.1' || host === '::1') {
    return { ok: false, blocked: true, reason: REASON.LOOPBACK, url: url.href };
  }
  if (opts.allowHosts && opts.allowHosts.length > 0) {
    const allowed = opts.allowHosts.some((entry) => {
      const suffix = String(entry || '').toLowerCase();
      if (suffix.startsWith('*.')) return host === suffix.slice(2) || host.endsWith('.' + suffix.slice(2));
      return host === suffix;
    });
    if (!allowed) return { ok: false, blocked: true, reason: REASON.HOST_NOT_ALLOWED, url: url.href, host };
  }
  if (!url.pathname.includes('dns-query')) {
    return { ok: false, blocked: true, reason: REASON.TEMPLATE_INVALID, url: url.href, path: url.pathname };
  }
  const params = url.searchParams;
  for (const key of params.keys()) {
    const value = params.get(key) || '';
    if (key.length > MAX_PARAM || value.length > MAX_PARAM || /[\u0000-\u001f]/.test(key + value)) {
      return { ok: false, blocked: true, reason: REASON.PARAM_UNSAFE, url: url.href, param: key };
    }
  }
  return { ok: true, blocked: false, reason: REASON.OK, url: url.href, host };
}

function auditDohBatch(list, options) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateDohEndpoint(item, options);
    if (result.blocked) {
      blocked += 1;
      findings.push({ url: result.url, reason: result.reason });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no doh risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.url || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  evaluateDohEndpoint,
  auditDohBatch,
  describeFindings,
};
