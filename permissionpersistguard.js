'use strict';

const REASON = {
  OK: 'ok',
  UNKNOWN_PERMISSION: 'permission-unknown',
  PERSIST_SENSITIVE: 'permission-persist-sensitive',
  STALE_GRANT: 'permission-stale-grant',
  EXPIRY_MISSING: 'permission-expiry-missing',
  EXPIRY_TOO_LONG: 'permission-expiry-too-long',
  ORIGIN_INVALID: 'permission-origin-invalid',
  GRANT_DENIED: 'permission-grant-denied',
};

const SENSITIVE = new Set(['media', 'geolocation', 'notifications', 'midi', 'hid', 'serial', 'usb', 'clipboard-read', 'audioCapture', 'videoCapture']);
const PERSISTABLE = new Set(['notifications', 'clipboard-read']);
const MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

function evaluateOrigin(value) {
  try {
    const url = new URL(String(value));
    if (!/^(https|file|chrome-extension):$/.test(url.protocol)) {
      return { ok: false, blocked: true, reason: REASON.ORIGIN_INVALID, origin: String(value) };
    }
    const local = url.protocol === 'file:' || url.hostname === 'localhost' || url.hostname === '127.0.0.1';
    if (!local && url.protocol !== 'https:') {
      return { ok: false, blocked: true, reason: REASON.ORIGIN_INVALID, origin: url.origin };
    }
    return { ok: true, blocked: false, reason: REASON.OK, origin: url.origin };
  } catch (err) {
    return { ok: false, blocked: true, reason: REASON.ORIGIN_INVALID, origin: String(value) };
  }
}

function evaluatePermissionGrant(grant, options) {
  const g = grant || {};
  const opts = options || {};
  const origin = evaluateOrigin(g.origin);
  if (origin.blocked) return origin;
  const permission = String(g.permission || '');
  if (!SENSITIVE.has(permission) && !PERSISTABLE.has(permission)) {
    return { ok: false, blocked: true, reason: REASON.UNKNOWN_PERMISSION, permission, origin: origin.origin };
  }
  if (g.decision === 'denied') return { ok: false, blocked: true, reason: REASON.GRANT_DENIED, permission, origin: origin.origin };
  if (g.persist === true && !PERSISTABLE.has(permission)) {
    return { ok: false, blocked: true, reason: REASON.PERSIST_SENSITIVE, permission, origin: origin.origin };
  }
  if (g.persist === true) {
    const expires = Number(g.expiresAt);
    if (!Number.isFinite(expires)) {
      return { ok: false, blocked: true, reason: REASON.EXPIRY_MISSING, permission, origin: origin.origin };
    }
    if (expires - Number(g.grantedAt || 0) > MAX_AGE_MS) {
      return { ok: false, blocked: true, reason: REASON.EXPIRY_TOO_LONG, permission, origin: origin.origin };
    }
    if (expires < Date.now() && opts.ignoreStale !== true) {
      return { ok: false, blocked: true, reason: REASON.STALE_GRANT, permission, origin: origin.origin };
    }
  }
  return { ok: true, blocked: false, reason: REASON.OK, permission, origin: origin.origin, persist: g.persist === true };
}

function auditPermissionBatch(list, options) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluatePermissionGrant(item, options);
    if (result.blocked) {
      blocked += 1;
      findings.push({ permission: result.permission, reason: result.reason, origin: result.origin });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no permission persistence risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.permission || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  MAX_AGE_MS,
  evaluatePermissionGrant,
  auditPermissionBatch,
  describeFindings,
};
