'use strict';

const REASON = {
  OK: 'ok',
  IDLE_DISABLED: 'idle-lock-disabled',
  TIMEOUT_INVALID: 'idle-timeout-invalid',
  TIMEOUT_TOO_LONG: 'idle-timeout-too-long',
  SENSITIVE_IDLE_LONG: 'idle-sensitive-window-long',
  LOCK_UNCONFIRMED: 'idle-lock-unconfirmed',
};

const MIN_IDLE_MS = 60 * 1000;
const MAX_IDLE_MS = 30 * 60 * 1000;
const SENSITIVE_MAX_MS = 5 * 60 * 1000;

function evaluateIdleLock(config) {
  const cfg = config || {};
  if (cfg.enabled !== true) {
    return { ok: false, blocked: true, reason: REASON.IDLE_DISABLED, enabled: false };
  }
  const timeout = Number(cfg.idleMs);
  if (!Number.isFinite(timeout) || timeout < MIN_IDLE_MS) {
    return { ok: false, blocked: true, reason: REASON.TIMEOUT_INVALID, idleMs: cfg.idleMs };
  }
  if (timeout > MAX_IDLE_MS) {
    return { ok: false, blocked: true, reason: REASON.TIMEOUT_TOO_LONG, idleMs: timeout };
  }
  if (cfg.sensitiveWindow === true && timeout > SENSITIVE_MAX_MS) {
    return { ok: false, blocked: true, reason: REASON.SENSITIVE_IDLE_LONG, idleMs: timeout };
  }
  if (cfg.lockOnIdle === false) {
    return { ok: false, blocked: true, reason: REASON.LOCK_UNCONFIRMED, idleMs: timeout };
  }
  return { ok: true, blocked: false, reason: REASON.OK, idleMs: timeout, lockOnIdle: cfg.lockOnIdle !== false };
}

function auditIdleLockBatch(list) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateIdleLock(item);
    if (result.blocked) {
      blocked += 1;
      findings.push({ reason: result.reason, idleMs: result.idleMs });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no idle lock risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.idleMs || 0) + ')')
    .join('; ');
}

module.exports = {
  REASON,
  MIN_IDLE_MS,
  MAX_IDLE_MS,
  evaluateIdleLock,
  auditIdleLockBatch,
  describeFindings,
};
