'use strict';

const MAX_SAN_CHARS = 64;
const MAX_DISPLAY_CHARS = 200;

const VERDICT = {
  TRUSTED: 'trusted',
  EXPIRED: 'expired',
  NOT_YET_VALID: 'not-yet-valid',
  HOSTNAME_MISMATCH: 'hostname-mismatch',
  WEAK_SIGNATURE: 'weak-signature',
  SELF_SIGNED: 'self-signed',
  UNKNOWN: 'unknown'
};

const WEAK_SIGNATURE_ALGORITHMS = new Set(['sha1', 'md5', 'md2', 'sha1-rsa', 'md5-rsa']);

function parseSubjectAltNames(raw) {
  if (typeof raw !== 'string' || raw.trim() === '') return [];
  const out = [];
  for (const entry of raw.split(',')) {
    const value = entry.trim();
    if (!value || value.length > MAX_SAN_CHARS) continue;
    if (out.includes(value)) continue;
    out.push(value);
  }
  return out.slice(0, 64);
}

function normalizeName(raw) {
  if (typeof raw !== 'string') return '';
  return raw.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, MAX_DISPLAY_CHARS);
}

function hostnameMatches(host, names) {
  if (typeof host !== 'string' || !Array.isArray(names) || names.length === 0) return false;
  const target = host.toLowerCase().replace(/\.$/, '');
  for (const name of names) {
    if (typeof name !== 'string') continue;
    const pattern = name.toLowerCase().replace(/\.$/, '');
    if (pattern === target) return true;
    if (pattern.startsWith('*.')) {
      const suffix = pattern.slice(1);
      if (target.endsWith(suffix)) {
        const prefix = target.slice(0, target.length - suffix.length);
        if (prefix.length > 0 && prefix.indexOf('.') < 0) return true;
      }
    }
  }
  return false;
}

function signatureIsWeak(algorithm) {
  if (typeof algorithm !== 'string') return false;
  return WEAK_SIGNATURE_ALGORITHMS.has(algorithm.trim().toLowerCase());
}

function inspectCertificate(cert, host, nowMs) {
  const now = Number.isFinite(Number(nowMs)) ? Number(nowMs) : Date.now();
  if (!cert || typeof cert !== 'object') {
    return { verdict: VERDICT.UNKNOWN, trusted: false, reasons: ['no-certificate'], subject: '', issuer: '' };
  }
  const reasons = [];
  let verdict = VERDICT.TRUSTED;
  if (cert.isSelfSigned === true) {
    verdict = VERDICT.SELF_SIGNED;
    reasons.push('self-signed');
  }
  const validFrom = Number.isFinite(Number(cert.validFromMs)) ? Number(cert.validFromMs) : null;
  const validTo = Number.isFinite(Number(cert.validToMs)) ? Number(cert.validToMs) : null;
  if (validTo !== null && now > validTo) {
    verdict = VERDICT.EXPIRED;
    reasons.push('expired');
  } else if (validFrom !== null && now < validFrom) {
    verdict = VERDICT.NOT_YET_VALID;
    reasons.push('not-yet-valid');
  }
  const names = parseSubjectAltNames(cert.subjectAltNames);
  if (host && !hostnameMatches(host, names)) {
    if (verdict === VERDICT.TRUSTED) verdict = VERDICT.HOSTNAME_MISMATCH;
    reasons.push('hostname-mismatch');
  }
  if (signatureIsWeak(cert.signatureAlgorithm)) {
    if (verdict === VERDICT.TRUSTED) verdict = VERDICT.WEAK_SIGNATURE;
    reasons.push('weak-signature');
  }
  return {
    verdict,
    trusted: verdict === VERDICT.TRUSTED,
    reasons,
    subject: normalizeName(cert.subject),
    issuer: normalizeName(cert.issuer),
    validFromMs: validFrom,
    validToMs: validTo,
    names
  };
}

function describeCertificate(result) {
  if (!result || result.verdict === VERDICT.UNKNOWN) return '无法读取证书信息';
  const label = {
    trusted: '证书有效',
    expired: '证书已过期',
    'not-yet-valid': '证书尚未生效',
    'hostname-mismatch': '证书与域名不匹配',
    'weak-signature': '证书使用了弱签名算法',
    'self-signed': '自签名证书，未被信任'
  }[result.verdict] || '证书状态未知';
  const issuer = result.issuer ? ' · 颁发者 ' + result.issuer : '';
  return label + issuer;
}

function shouldBlockNavigation(result) {
  if (!result || typeof result !== 'object') return true;
  return result.trusted !== true;
}

function daysUntilExpiry(result, nowMs) {
  if (!result || !Number.isFinite(Number(result.validToMs))) return null;
  const now = Number.isFinite(Number(nowMs)) ? Number(nowMs) : Date.now();
  return Math.floor((Number(result.validToMs) - now) / 86400000);
}

module.exports = {
  VERDICT,
  MAX_SAN_CHARS,
  parseSubjectAltNames,
  hostnameMatches,
  signatureIsWeak,
  inspectCertificate,
  describeCertificate,
  shouldBlockNavigation,
  daysUntilExpiry
};
