'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'wake-lock-empty',
  INSECURE: 'wake-lock-insecure',
  HIDDEN_DOCUMENT: 'wake-lock-hidden',
  BAD_TYPE: 'wake-lock-bad-type',
  NO_GESTURE: 'wake-lock-no-gesture',
};

const TYPES = ['screen', 'system'];

function evaluateWakeLock(request, options) {
  const opts = options || {};
  const req = request || {};
  const origin = typeof req.origin === 'string' ? req.origin.trim() : '';
  if (origin === '') return { ok: false, blocked: true, reason: REASON.EMPTY };
  if (!origin.toLowerCase().startsWith('https://')) {
    return { ok: false, blocked: true, reason: REASON.INSECURE, origin: origin.slice(0, 48) };
  }
  if (req.visible === false) {
    return { ok: false, blocked: true, reason: REASON.HIDDEN_DOCUMENT, origin };
  }
  const type = String(req.type || 'screen').toLowerCase();
  if (!TYPES.includes(type)) {
    return { ok: false, blocked: true, reason: REASON.BAD_TYPE, type: type.slice(0, 24) };
  }
  if (opts.requireGesture === true && req.userGesture !== true) {
    return { ok: false, blocked: true, reason: REASON.NO_GESTURE, origin };
  }
  return { ok: true, blocked: false, reason: REASON.OK, origin, type };
}

function releaseAll(locks) {
  const list = Array.isArray(locks) ? locks : [];
  let released = 0;
  for (const lock of list) {
    if (lock && typeof lock.release === 'function') {
      released += 1;
    }
  }
  return { requested: list.length, released };
}

module.exports = {
  REASON,
  TYPES,
  evaluateWakeLock,
  releaseAll,
};
