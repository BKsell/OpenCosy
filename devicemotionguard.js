'use strict';

const REASON = {
  OK: 'ok',
  ORIGIN_INVALID: 'motion-origin-invalid',
  INSECURE_ORIGIN: 'motion-insecure-origin',
  PERMISSION_DENIED: 'motion-permission-denied',
  RATE_TOO_HIGH: 'motion-rate-too-high',
  RATE_INVALID: 'motion-rate-invalid',
  CAPTURE_TOO_LONG: 'motion-capture-too-long',
};

const MAX_RATE = 120;
const MAX_CAPTURE_MS = 10 * 60 * 1000;

function evaluateMotionRequest(request) {
  const req = request || {};
  let url;
  try {
    url = new URL(String(req.origin || ''));
  } catch (err) {
    return { ok: false, blocked: true, reason: REASON.ORIGIN_INVALID, origin: String(req.origin || '') };
  }
  const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  if (url.protocol !== 'https:' && !local) {
    return { ok: false, blocked: true, reason: REASON.INSECURE_ORIGIN, origin: url.origin };
  }
  if (req.permission === 'denied' || req.granted === false) {
    return { ok: false, blocked: true, reason: REASON.PERMISSION_DENIED, origin: url.origin };
  }
  const rate = req.rateHz === undefined ? 60 : Number(req.rateHz);
  if (!Number.isFinite(rate) || rate <= 0) {
    return { ok: false, blocked: true, reason: REASON.RATE_INVALID, origin: url.origin, rateHz: req.rateHz };
  }
  if (rate > MAX_RATE) {
    return { ok: false, blocked: true, reason: REASON.RATE_TOO_HIGH, origin: url.origin, rateHz: rate };
  }
  if (req.captureMs !== undefined && Number(req.captureMs) > MAX_CAPTURE_MS) {
    return { ok: false, blocked: true, reason: REASON.CAPTURE_TOO_LONG, origin: url.origin, captureMs: req.captureMs };
  }
  return { ok: true, blocked: false, reason: REASON.OK, origin: url.origin, rateHz: rate };
}

function auditMotionBatch(list) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateMotionRequest(item);
    if (result.blocked) {
      blocked += 1;
      findings.push({ origin: result.origin, reason: result.reason });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no device motion risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.origin || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  MAX_RATE,
  evaluateMotionRequest,
  auditMotionBatch,
  describeFindings,
};
