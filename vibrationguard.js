'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'vibration-empty',
  INSECURE: 'vibration-insecure',
  TOO_LONG: 'vibration-too-long',
  NEGATIVE: 'vibration-negative',
  HIDDEN: 'vibration-hidden',
};

const MAX_PATTERN = 5;
const MAX_DURATION = 5000;

function evaluateVibration(request, options) {
  const opts = options || {};
  const req = request || {};
  const origin = typeof req.origin === 'string' ? req.origin.trim() : '';
  if (origin === '') return { ok: false, blocked: true, reason: REASON.EMPTY };
  if (!origin.toLowerCase().startsWith('https://')) {
    return { ok: false, blocked: true, reason: REASON.INSECURE, origin: origin.slice(0, 48) };
  }
  if (req.visible === false && opts.allowHidden !== true) {
    return { ok: false, blocked: true, reason: REASON.HIDDEN, origin };
  }
  const pattern = Array.isArray(req.pattern) ? req.pattern : [Number(req.pattern || 0)];
  if (pattern.length > MAX_PATTERN) {
    return { ok: false, blocked: true, reason: REASON.TOO_LONG, count: pattern.length, limit: MAX_PATTERN };
  }
  let total = 0;
  for (const entry of pattern) {
    const value = Number(entry);
    if (!Number.isFinite(value) || value < 0) {
      return { ok: false, blocked: true, reason: REASON.NEGATIVE, value: String(entry).slice(0, 12) };
    }
    total += value;
  }
  if (total > MAX_DURATION) {
    return { ok: false, blocked: true, reason: REASON.TOO_LONG, total, limit: MAX_DURATION };
  }
  return { ok: true, blocked: false, reason: REASON.OK, origin, total, segments: pattern.length };
}

function normalizePattern(pattern) {
  const list = Array.isArray(pattern) ? pattern : [];
  let out = [];
  for (const entry of list) {
    const value = Math.max(0, Math.min(Number(entry) || 0, MAX_DURATION));
    if (value === 0 && out.length > 0) continue;
    out.push(value);
  }
  if (out.length > MAX_PATTERN) out = out.slice(0, MAX_PATTERN);
  return out;
}

module.exports = {
  REASON,
  MAX_PATTERN,
  MAX_DURATION,
  evaluateVibration,
  normalizePattern,
};
