'use strict';

const REASON = {
  OK: 'ok',
  ORIGIN_INVALID: 'webauthn-origin-invalid',
  RP_ID_MISMATCH: 'webauthn-rpid-mismatch',
  RP_ID_PUBLIC_SUFFIX: 'webauthn-rpid-public-suffix',
  INSECURE_ORIGIN: 'webauthn-insecure-origin',
  OPTS_INVALID: 'webauthn-options-invalid',
  CHALLENGE_WEAK: 'webauthn-challenge-weak',
  TIMEOUT_TOO_LONG: 'webauthn-timeout-too-long',
};

const MAX_TIMEOUT = 300000;
const PUBLIC_SUFFIX = new Set(['com', 'org', 'net', 'io', 'cn', 'co', 'uk', 'gov', 'edu']);
const MIN_CHALLENGE = 16;

function registrable(host) {
  const parts = String(host || '').toLowerCase().split('.').filter(Boolean);
  if (parts.length <= 2) return parts.join('.');
  const last = parts[parts.length - 1];
  const second = parts[parts.length - 2];
  if (PUBLIC_SUFFIX.has(second) && last.length === 2) return parts.slice(-3).join('.');
  return parts.slice(-2).join('.');
}

function evaluateWebauthn(input) {
  const item = input || {};
  let url;
  try {
    url = new URL(String(item.origin || ''));
  } catch (err) {
    return { ok: false, blocked: true, reason: REASON.ORIGIN_INVALID, origin: String(item.origin || '') };
  }
  const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  if (url.protocol !== 'https:' && !local) {
    return { ok: false, blocked: true, reason: REASON.INSECURE_ORIGIN, origin: url.origin };
  }
  const rpId = String(item.rpId || '').toLowerCase();
  if (rpId === '') return { ok: false, blocked: true, reason: REASON.RP_ID_MISMATCH, rpId };
  const host = url.hostname.toLowerCase();
  if (host !== rpId && !host.endsWith('.' + rpId)) {
    return { ok: false, blocked: true, reason: REASON.RP_ID_MISMATCH, rpId, host };
  }
  if (rpId.split('.').length === 1 && PUBLIC_SUFFIX.has(rpId)) {
    return { ok: false, blocked: true, reason: REASON.RP_ID_PUBLIC_SUFFIX, rpId };
  }
  if (registrable(host) !== rpId && rpId !== host) {
    return { ok: false, blocked: true, reason: REASON.RP_ID_MISMATCH, rpId, host };
  }
  if (item.challenge !== undefined) {
    const challenge = String(item.challenge);
    if (challenge.length < MIN_CHALLENGE || /^(.)\1+$/.test(challenge)) {
      return { ok: false, blocked: true, reason: REASON.CHALLENGE_WEAK, rpId };
    }
  }
  if (item.timeout !== undefined && Number(item.timeout) > MAX_TIMEOUT) {
    return { ok: false, blocked: true, reason: REASON.TIMEOUT_TOO_LONG, timeout: item.timeout };
  }
  if (item.userVerification && !['required', 'preferred', 'discouraged'].includes(String(item.userVerification))) {
    return { ok: false, blocked: true, reason: REASON.OPTS_INVALID, userVerification: item.userVerification };
  }
  return { ok: true, blocked: false, reason: REASON.OK, origin: url.origin, rpId };
}

function auditWebauthnBatch(list) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateWebauthn(item);
    if (result.blocked) {
      blocked += 1;
      findings.push({ origin: result.origin, rpId: result.rpId, reason: result.reason });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no webauthn origin risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.rpId || f.origin || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  evaluateWebauthn,
  auditWebauthnBatch,
  describeFindings,
  registrable,
};
