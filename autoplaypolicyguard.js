'use strict';

const REASON = {
  OK: 'ok',
  AUTOPLAY_ALLOWED: 'autoplay-unrestricted',
  MUTED_REQUIRED: 'autoplay-unmuted',
  GESTURE_REQUIRED: 'autoplay-no-gesture',
  VOLUME_TOO_HIGH: 'autoplay-volume-too-high',
  ORIGIN_INVALID: 'autoplay-origin-invalid',
};

const MAX_VOLUME = 0.5;

function evaluateAutoplay(request) {
  const req = request || {};
  let url;
  try {
    url = new URL(String(req.origin || ''));
  } catch (err) {
    return { ok: false, blocked: true, reason: REASON.ORIGIN_INVALID, origin: String(req.origin || '') };
  }
  if (req.allowAll === true) {
    return { ok: false, blocked: true, reason: REASON.AUTOPLAY_ALLOWED, origin: url.origin };
  }
  const volume = req.volume === undefined ? 0 : Number(req.volume);
  if (req.muted === false && volume > MAX_VOLUME) {
    return { ok: false, blocked: true, reason: REASON.VOLUME_TOO_HIGH, origin: url.origin, volume };
  }
  if (req.muted === false && req.userGesture !== true) {
    return { ok: false, blocked: true, reason: REASON.GESTURE_REQUIRED, origin: url.origin };
  }
  if (req.muted !== true && req.userGesture !== true) {
    return { ok: false, blocked: true, reason: REASON.MUTED_REQUIRED, origin: url.origin };
  }
  return { ok: true, blocked: false, reason: REASON.OK, origin: url.origin, muted: req.muted === true };
}

function auditAutoplayBatch(list) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateAutoplay(item);
    if (result.blocked) {
      blocked += 1;
      findings.push({ origin: result.origin, reason: result.reason });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no autoplay risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.origin || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  MAX_VOLUME,
  evaluateAutoplay,
  auditAutoplayBatch,
  describeFindings,
};
