'use strict';

const REASON = {
  OK: 'ok',
  HOST_MISSING: 'pin-host-missing',
  HOST_INVALID: 'pin-host-invalid',
  NO_PINS: 'pin-set-empty',
  PIN_INVALID: 'pin-format-invalid',
  WEAK_HASH: 'pin-weak-hash',
  NO_BACKUP: 'pin-no-backup',
  EXPIRY_INVALID: 'pin-expiry-invalid',
  EXPIRY_SOON: 'pin-expiry-near',
};

const MAX_PINS = 12;
const MIN_BACKUP = 2;
const NEAR_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000;
const STRONG = new Set(['sha256', 'sha384', 'sha512']);

function parseHost(value) {
  if (typeof value !== 'string' || value.trim() === '') return null;
  const host = value.trim().toLowerCase();
  if (/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(host) === false) return null;
  return host;
}

function parsePin(pin) {
  const text = String(pin || '').trim();
  const dash = text.indexOf('-');
  if (dash <= 0) return { algorithm: '', digest: '' };
  return { algorithm: text.slice(0, dash).toLowerCase(), digest: text.slice(dash + 1) };
}

function evaluatePinningPolicy(policy, now) {
  const cfg = policy || {};
  const host = parseHost(cfg.host);
  if (host === null) {
    return { ok: false, blocked: true, reason: cfg.host === undefined ? REASON.HOST_MISSING : REASON.HOST_INVALID, host: cfg.host };
  }
  const pins = Array.isArray(cfg.pins) ? cfg.pins : [];
  if (pins.length === 0) return { ok: false, blocked: true, reason: REASON.NO_PINS, host };
  if (pins.length > MAX_PINS) return { ok: false, blocked: true, reason: REASON.PIN_INVALID, host, count: pins.length };
  for (const pin of pins) {
    const parsed = parsePin(pin);
    if (parsed.digest === '' || parsed.algorithm === '') {
      return { ok: false, blocked: true, reason: REASON.PIN_INVALID, host, pin: String(pin) };
    }
    if (!STRONG.has(parsed.algorithm)) {
      return { ok: false, blocked: true, reason: REASON.WEAK_HASH, host, pin: String(pin), algorithm: parsed.algorithm };
    }
    if (/\s/.test(parsed.digest) || parsed.digest.length < 43) {
      return { ok: false, blocked: true, reason: REASON.PIN_INVALID, host, pin: String(pin) };
    }
  }
  if (pins.length < MIN_BACKUP) {
    return { ok: false, blocked: true, reason: REASON.NO_BACKUP, host, count: pins.length };
  }
  const reference = now === undefined ? Date.now() : Number(now);
  if (cfg.expiresAt !== undefined) {
    const expires = Number(cfg.expiresAt);
    if (!Number.isFinite(expires) || expires <= reference) {
      return { ok: false, blocked: true, reason: REASON.EXPIRY_INVALID, host, expiresAt: cfg.expiresAt };
    }
    if (expires - reference < NEAR_EXPIRY_MS) {
      return { ok: false, blocked: true, reason: REASON.EXPIRY_SOON, host, expiresAt: expires };
    }
  }
  return { ok: true, blocked: false, reason: REASON.OK, host, count: pins.length };
}

function auditPinningBatch(list, now) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluatePinningPolicy(item, now);
    if (result.blocked) {
      blocked += 1;
      findings.push({ host: result.host, reason: result.reason });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no pinning risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.host || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  MIN_BACKUP,
  evaluatePinningPolicy,
  auditPinningBatch,
  describeFindings,
};
