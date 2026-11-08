'use strict';

const REASON = {
  OK: 'ok',
  UNKNOWN_PERMISSION: 'unknown-permission',
  ORIGIN_MISSING: 'origin-missing',
  INSECURE_ORIGIN: 'insecure-origin',
  SENSITIVE_DENIED: 'sensitive-permission-denied',
  PERSISTED_DENIED: 'persisted-permission-denied',
  USER_PROMPT: 'user-confirmation-required',
};

const SENSITIVE = new Set(['media', 'geolocation', 'notifications', 'midi', 'midiSysex', 'hid', 'serial', 'usb', 'bluetooth', 'idle-detection', 'speaker-selection']);
const BENIGN = new Set(['clipboard-sanitized-write', 'fullscreen', 'pointerLock', 'openExternal']);

function parse(value) {
  if (typeof value !== 'string' || !value) return null;
  try {
    return new URL(value);
  } catch (err) {
    return null;
  }
}

function evaluate(request) {
  const req = request && typeof request === 'object' ? request : {};
  const permission = String(req.permission || '');
  if (!SENSITIVE.has(permission) && !BENIGN.has(permission)) {
    return { decision: 'deny', reason: REASON.UNKNOWN_PERMISSION, permission };
  }
  const origin = parse(req.origin);
  if (!origin) return { decision: 'deny', reason: REASON.ORIGIN_MISSING, permission };
  if (origin.protocol !== 'https:' && req.allowInsecure !== true) {
    return { decision: 'deny', reason: REASON.INSECURE_ORIGIN, permission };
  }
  if (BENIGN.has(permission) && req.isMainFrame !== false) {
    return { decision: req.requirePrompt === false ? 'allow' : 'prompt', reason: REASON.OK, permission };
  }
  if (SENSITIVE.has(permission)) {
    if (Array.isArray(req.blockedOrigins) && req.blockedOrigins.includes(origin.hostname)) {
      return { decision: 'deny', reason: REASON.SENSITIVE_DENIED, permission };
    }
    if (req.persist === true && permission !== 'fullscreen') {
      return { decision: 'deny', reason: REASON.PERSISTED_DENIED, permission };
    }
    return { decision: 'prompt', reason: REASON.USER_PROMPT, permission };
  }
  return { decision: 'deny', reason: REASON.UNKNOWN_PERMISSION, permission };
}

function applyPermissionsRequestGuard(request) {
  const req = request && typeof request === 'object' ? request : {};
  const result = evaluate(req);
  const details = [];
  if (result.decision !== 'allow') details.push(result.permission);
  return {
    decision: result.decision,
    allowed: result.decision === 'allow',
    reason: result.reason,
    permission: result.permission,
    details,
  };
}

function auditPermissionBatch(requests, options) {
  const list = Array.isArray(requests) ? requests : [];
  const findings = [];
  let denied = 0;
  let prompted = 0;
  for (const item of list) {
    const result = evaluate(item);
    if (result.decision === 'deny') denied += 1;
    if (result.decision === 'prompt') prompted += 1;
    if (result.reason !== REASON.OK) findings.push({ permission: item && item.permission, reason: result.reason });
  }
  const limit = Number(options && options.maxFindings) || 10;
  return { denied, prompted, total: list.length, findings: findings.slice(0, limit) };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no permission risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applyPermissionsRequestGuard,
  auditPermissionBatch,
  describeFindings,
};
