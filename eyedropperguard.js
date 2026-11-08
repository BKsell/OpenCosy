'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'eyedropper-empty',
  INSECURE: 'eyedropper-insecure',
  NO_GESTURE: 'eyedropper-no-gesture',
  CLOSED_STREAM: 'eyedropper-closed',
};

function evaluateEyedropper(request, options) {
  const opts = options || {};
  const req = request || {};
  const origin = typeof req.origin === 'string' ? req.origin.trim() : '';
  if (origin === '') return { ok: false, blocked: true, reason: REASON.EMPTY };
  if (!origin.toLowerCase().startsWith('https://')) {
    return { ok: false, blocked: true, reason: REASON.INSECURE, origin: origin.slice(0, 48) };
  }
  if (req.aborted === true) {
    return { ok: false, blocked: true, reason: REASON.CLOSED_STREAM, origin };
  }
  if (opts.requireGesture !== false && req.userGesture !== true) {
    return { ok: false, blocked: true, reason: REASON.NO_GESTURE, origin };
  }
  return { ok: true, blocked: false, reason: REASON.OK, origin };
}

function colorFromResult(result) {
  const data = result || {};
  const sRGB = data.sRGBHex || '';
  if (!/^#[0-9a-fA-F]{6}$/.test(sRGB)) return null;
  return { hex: sRGB.toLowerCase(), r: parseInt(sRGB.slice(1, 3), 16), g: parseInt(sRGB.slice(3, 5), 16), b: parseInt(sRGB.slice(5, 7), 16) };
}

module.exports = {
  REASON,
  evaluateEyedropper,
  colorFromResult,
};
