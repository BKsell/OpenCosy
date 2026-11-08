'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'screen-details-empty',
  INSECURE: 'screen-details-insecure',
  NO_GESTURE: 'screen-details-no-gesture',
  TOO_MANY_SCREENS: 'screen-details-too-many',
  BAD_FIELD: 'screen-details-bad-field',
};

const MAX_SCREENS = 8;

function evaluateScreenDetails(request, options) {
  const opts = options || {};
  const req = request || {};
  const origin = typeof req.origin === 'string' ? req.origin.trim() : '';
  if (origin === '') return { ok: false, blocked: true, reason: REASON.EMPTY };
  if (!origin.toLowerCase().startsWith('https://')) {
    return { ok: false, blocked: true, reason: REASON.INSECURE, origin: origin.slice(0, 48) };
  }
  if (opts.requireGesture !== false && req.userGesture !== true) {
    return { ok: false, blocked: true, reason: REASON.NO_GESTURE, origin };
  }
  const screens = Array.isArray(req.screens) ? req.screens : [];
  if (screens.length === 0) return { ok: false, blocked: true, reason: REASON.EMPTY, origin };
  if (screens.length > MAX_SCREENS) {
    return { ok: false, blocked: true, reason: REASON.TOO_MANY_SCREENS, count: screens.length };
  }
  for (const screen of screens) {
    if (!screen || typeof screen !== 'object') {
      return { ok: false, blocked: true, reason: REASON.BAD_FIELD, field: 'screen' };
    }
    for (const key of ['width', 'height', 'availWidth', 'availHeight']) {
      if (key in screen && (!Number.isInteger(screen[key]) || screen[key] <= 0)) {
        return { ok: false, blocked: true, reason: REASON.BAD_FIELD, field: key, value: String(screen[key]).slice(0, 12) };
      }
    }
  }
  return { ok: true, blocked: false, reason: REASON.OK, origin, screens: screens.length };
}

function placeWindow(bounds, screen) {
  const item = bounds || {};
  const frame = screen || {};
  const width = Math.max(1, Math.min(Number(item.width) || 800, Number(frame.availWidth) || 1920));
  const height = Math.max(1, Math.min(Number(item.height) || 600, Number(frame.availHeight) || 1080));
  const left = Math.max(0, Math.min(Number(item.left) || 0, (Number(frame.availWidth) || 1920) - width));
  const top = Math.max(0, Math.min(Number(item.top) || 0, (Number(frame.availHeight) || 1080) - height));
  return { left, top, width, height };
}

module.exports = {
  REASON,
  MAX_SCREENS,
  evaluateScreenDetails,
  placeWindow,
};
