'use strict';
const { describeReasons } = require('./findingsview');

const REASON = {
  OK: 'ok',
  EMPTY: 'sslstrip-url-empty',
  INVALID: 'sslstrip-url-invalid',
  DOWNGRADE: 'sslstrip-downgrade',
  HSTS_BYPASS: 'sslstrip-hsts-bypass',
  CREDENTIALS: 'sslstrip-credentials',
};

const HSTS_HOSTS = ['example.com', 'bank.example.com'];

function isHstsHost(host) {
  const lower = String(host || '').toLowerCase();
  return HSTS_HOSTS.some((entry) => lower === entry || lower.endsWith('.' + entry));
}

function upgradeToHttps(value) {
  const text = String(value || '').trim();
  if (text === '') return { ok: false, blocked: true, reason: REASON.EMPTY, url: '' };
  if (text.startsWith('https:')) return { ok: true, blocked: false, reason: REASON.OK, url: text };
  if (text.startsWith('http:')) return { ok: true, blocked: false, reason: REASON.OK, url: 'https:' + text.slice(5), upgraded: true };
  return { ok: false, blocked: true, reason: REASON.INVALID, url: text.slice(0, 64) };
}

function evaluateTransition(from, to) {
  const upgrade = upgradeToHttps(to);
  if (!upgrade.ok) return upgrade;
  let target;
  try {
    target = new URL(String(to || ''));
  } catch (err) {
    return { ok: false, blocked: true, reason: REASON.INVALID, url: String(to || '').slice(0, 64) };
  }
  if (target.username || target.password) {
    return { ok: false, blocked: true, reason: REASON.CREDENTIALS, url: target.origin + target.pathname };
  }
  if (String(from || '').startsWith('https:') && target.protocol === 'http:') {
    return { ok: false, blocked: true, reason: REASON.DOWNGRADE, url: target.href, host: target.hostname };
  }
  if (isHstsHost(target.hostname) && target.protocol !== 'https:') {
    return { ok: false, blocked: true, reason: REASON.HSTS_BYPASS, url: target.href, host: target.hostname };
  }
  return { ok: true, blocked: false, reason: REASON.OK, url: target.href, host: target.hostname };
}

function auditTransitionBatch(list) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateTransition(item && item.from, item && item.to);
    if (result.blocked) {
      blocked += 1;
      findings.push({ url: result.url, reason: result.reason });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  return describeReasons(findings, 'no ssl strip risk',
    (f) => f.reason + '(' + String(f.url || '') + ')');
}

module.exports = {
  REASON,
  upgradeToHttps,
  evaluateTransition,
  auditTransitionBatch,
  describeFindings,
};
