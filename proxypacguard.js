'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'empty-pac-url',
  INVALID: 'invalid-pac-url',
  PLAINTEXT: 'pac-plaintext',
  CREDENTIALS: 'pac-credentials',
  LOCAL_FILE: 'pac-local-file',
  LOOPBACK: 'pac-loopback',
  DATA_SCRIPT: 'pac-inline-script',
};

const MAX_URL = 8192;
const ALLOWED = new Set(['https:', 'http:']);

function evaluateProxyPac(value, options) {
  const opts = options || {};
  if (value === null || value === undefined || value === '') {
    return { ok: true, blocked: false, reason: REASON.EMPTY, url: null };
  }
  if (typeof value !== 'string' || value.length > MAX_URL) {
    return { ok: false, blocked: true, reason: REASON.INVALID, url: null };
  }
  const trimmed = value.trim();
  if (/^(data|javascript|blob|file):/i.test(trimmed)) {
    const reason = /^file:/i.test(trimmed) ? REASON.LOCAL_FILE : REASON.DATA_SCRIPT;
    return { ok: false, blocked: true, reason, url: trimmed };
  }
  let url;
  try {
    url = new URL(trimmed);
  } catch (err) {
    return { ok: false, blocked: true, reason: REASON.INVALID, url: trimmed };
  }
  if (!ALLOWED.has(url.protocol)) {
    return { ok: false, blocked: true, reason: REASON.INVALID, url: url.href };
  }
  if (url.username || url.password) {
    return { ok: false, blocked: true, reason: REASON.CREDENTIALS, url: url.href };
  }
  if (url.protocol === 'http:' && opts.allowPlaintextPac !== true) {
    return { ok: false, blocked: true, reason: REASON.PLAINTEXT, url: url.href };
  }
  const host = url.hostname.toLowerCase();
  const loopback = host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]';
  if (loopback && opts.allowLoopbackPac !== true) {
    return { ok: false, blocked: true, reason: REASON.LOOPBACK, url: url.href };
  }
  return { ok: true, blocked: false, reason: REASON.OK, url: url.href };
}

function evaluateProxyConfig(config) {
  const cfg = config || {};
  const pac = evaluateProxyPac(cfg.pacUrl, cfg);
  if (cfg.pacUrl && pac.blocked) return { ...pac, field: 'pacUrl' };
  const rules = String(cfg.proxyRules || '');
  if (rules.length > 0 && /<[^>]*>/.test(rules)) {
    return { ok: false, blocked: true, reason: REASON.DATA_SCRIPT, url: null, field: 'proxyRules' };
  }
  if (cfg.mode === 'fixed_servers' && !cfg.proxyRules && !cfg.pacUrl) {
    return { ok: false, blocked: true, reason: REASON.EMPTY, url: null, field: 'mode' };
  }
  return { ok: true, blocked: false, reason: REASON.OK, url: pac.url || null };
}

function auditProxyBatch(list) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateProxyConfig(item);
    if (result.blocked) {
      blocked += 1;
      findings.push({ field: result.field, reason: result.reason });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no proxy risk';
  return list
    .slice(0, 8)
    .map((f) => String(f.field || 'pac') + ':' + f.reason)
    .join('; ');
}

module.exports = {
  REASON,
  evaluateProxyPac,
  evaluateProxyConfig,
  auditProxyBatch,
  describeFindings,
};
