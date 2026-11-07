'use strict';

const REASON = {
  OK: 'ok',
  TLS_TOO_OLD: 'tls-version-too-old',
  TLS_UNKNOWN: 'tls-version-unknown',
  WEAK_CIPHER: 'tls-weak-cipher',
  NULL_CIPHER: 'tls-null-cipher',
  EXPORT_CIPHER: 'tls-export-cipher',
  NO_VERIFY: 'tls-verification-disabled',
};

const MIN_VERSION = 'TLSv1.2';
const ORDER = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];
const WEAK = new Set(['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon']);
const WEAK_SUBSTRINGS = ['_RC4_', '_DES_', '_3DES_', '_MD5', '_NULL_', '_EXPORT_', '_anon_'];

function isAtLeast(version) {
  const idx = ORDER.indexOf(String(version || '').trim());
  return idx >= ORDER.indexOf(MIN_VERSION);
}

function evaluateTlsConfig(config) {
  const cfg = config || {};
  const version = String(cfg.minVersion || '').trim();
  if (version === '') return { ok: false, blocked: true, reason: REASON.TLS_UNKNOWN, minVersion: version };
  if (!ORDER.includes(version)) return { ok: false, blocked: true, reason: REASON.TLS_UNKNOWN, minVersion: version };
  if (!isAtLeast(version)) return { ok: false, blocked: true, reason: REASON.TLS_TOO_OLD, minVersion: version };
  if (cfg.rejectUnauthorized === false || cfg.verify === false) {
    return { ok: false, blocked: true, reason: REASON.NO_VERIFY, minVersion: version };
  }
  const ciphers = String(cfg.ciphers || '');
  if (ciphers.length > 0) {
    const tokens = ciphers.split(/[:,]/).map((item) => item.trim().toUpperCase()).filter(Boolean);
    for (const token of tokens) {
      if (WEAK.has(token)) return { ok: false, blocked: true, reason: REASON.WEAK_CIPHER, cipher: token };
      const segments = token.split('-');
      if (segments.some((segment) => WEAK.has(segment))) {
        return { ok: false, blocked: true, reason: REASON.WEAK_CIPHER, cipher: token };
      }
      if (WEAK_SUBSTRINGS.some((hint) => token.includes(hint))) {
        return { ok: false, blocked: true, reason: REASON.WEAK_CIPHER, cipher: token };
      }
      if (token.endsWith('NULL') || token.includes('aNULL')) {
        return { ok: false, blocked: true, reason: REASON.NULL_CIPHER, cipher: token };
      }
      if (token.includes('EXPORT')) return { ok: false, blocked: true, reason: REASON.EXPORT_CIPHER, cipher: token };
    }
  }
  return { ok: true, blocked: false, reason: REASON.OK, minVersion: version };
}

function auditTlsBatch(list) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateTlsConfig(item);
    if (result.blocked) {
      blocked += 1;
      findings.push({ minVersion: result.minVersion, reason: result.reason, cipher: result.cipher });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no tls config risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.cipher || f.minVersion || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  MIN_VERSION,
  isAtLeast,
  evaluateTlsConfig,
  auditTlsBatch,
  describeFindings,
};
