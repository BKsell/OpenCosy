'use strict';

const REASON = {
  OK: 'ok',
  NOT_ENABLED: 'media-keys-not-enabled',
  UNTRUSTED_FOCUS: 'media-keys-untrusted-focus',
  NO_REGISTERED_HANDLER: 'media-keys-no-handler',
  BACKDROP_DUPLICATE: 'media-keys-duplicate',
  CONTROL_CHARS: 'media-keys-control-chars',
};

const MAX_ACTIONS = 8;
const ACTIONS = new Set(['play', 'pause', 'play-pause', 'stop', 'next', 'previous', 'seek-forward', 'seek-backward']);

function evaluateMediaKeyRequest(request) {
  const req = request || {};
  if (req.enabled !== true) {
    return { ok: false, blocked: true, reason: REASON.NOT_ENABLED, action: req.action };
  }
  const action = String(req.action || '').toLowerCase();
  if (!ACTIONS.has(action)) {
    return { ok: false, blocked: true, reason: REASON.NO_REGISTERED_HANDLER, action };
  }
  if (/[\u0000-\u001f]/.test(action)) {
    return { ok: false, blocked: true, reason: REASON.CONTROL_CHARS, action };
  }
  if (req.trustedFocus !== true) {
    return { ok: false, blocked: true, reason: REASON.UNTRUSTED_FOCUS, action };
  }
  return { ok: true, blocked: false, reason: REASON.OK, action };
}

function evaluateRegistration(actions) {
  const list = Array.isArray(actions) ? actions : [];
  if (list.length === 0) return { ok: false, blocked: true, reason: REASON.NO_REGISTERED_HANDLER, count: 0 };
  const unique = new Set();
  for (const action of list) {
    const name = String(action || '').toLowerCase();
    if (unique.has(name)) return { ok: false, blocked: true, reason: REASON.BACKDROP_DUPLICATE, action: name };
    unique.add(name);
    if (!ACTIONS.has(name)) return { ok: false, blocked: true, reason: REASON.NO_REGISTERED_HANDLER, action: name };
  }
  return { ok: unique.size <= MAX_ACTIONS, blocked: unique.size > MAX_ACTIONS, reason: unique.size > MAX_ACTIONS ? REASON.BACKDROP_DUPLICATE : REASON.OK, count: unique.size };
}

function auditMediaKeyBatch(list) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateMediaKeyRequest(item);
    if (result.blocked) {
      blocked += 1;
      findings.push({ reason: result.reason, action: result.action });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no media key risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.action || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  ACTIONS,
  evaluateMediaKeyRequest,
  evaluateRegistration,
  auditMediaKeyBatch,
  describeFindings,
};
