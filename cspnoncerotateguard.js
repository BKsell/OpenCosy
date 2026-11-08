'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'nonce-empty',
  TOO_SHORT: 'nonce-too-short',
  LOW_ENTROPY: 'nonce-low-entropy',
  DUPLICATE: 'nonce-duplicate',
  PLACEHOLDER: 'nonce-placeholder',
};

const MIN_NONCE = 16;
const MIN_UNIQUE = 8;

function nonceEntropy(nonce) {
  const unique = new Set(nonce.split('')).size;
  return { unique, total: nonce.length, ratio: nonce.length === 0 ? 0 : unique / nonce.length };
}

function evaluateNonce(nonce) {
  if (typeof nonce !== 'string' || nonce.trim() === '') {
    return { ok: false, blocked: true, reason: REASON.EMPTY };
  }
  const value = nonce.trim();
  if (/^(none|nil|null|undefined|nonce|test|0+)$/i.test(value)) {
    return { ok: false, blocked: true, reason: REASON.PLACEHOLDER, nonce: value.slice(0, 16) };
  }
  if (value.length < MIN_NONCE) {
    return { ok: false, blocked: true, reason: REASON.TOO_SHORT, length: value.length, required: MIN_NONCE };
  }
  const entropy = nonceEntropy(value);
  if (entropy.unique < MIN_UNIQUE || entropy.ratio < 0.25) {
    return { ok: false, blocked: true, reason: REASON.LOW_ENTROPY, unique: entropy.unique, length: value.length };
  }
  return { ok: true, blocked: false, reason: REASON.OK, length: value.length, unique: entropy.unique };
}

function auditNonceRotation(list) {
  const items = Array.isArray(list) ? list : [];
  const seen = new Map();
  const findings = [];
  for (let i = 0; i < items.length; i += 1) {
    const result = evaluateNonce(items[i]);
    if (!result.ok) {
      findings.push({ index: i, reason: result.reason });
      continue;
    }
    const key = String(items[i]).trim();
    if (seen.has(key)) {
      findings.push({ index: i, reason: REASON.DUPLICATE, firstIndex: seen.get(key) });
    } else {
      seen.set(key, i);
    }
  }
  return { total: items.length, unique: seen.size, findings };
}

module.exports = {
  REASON,
  MIN_NONCE,
  evaluateNonce,
  nonceEntropy,
  auditNonceRotation,
};
