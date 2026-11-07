'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'font-access-empty',
  INSECURE: 'font-access-insecure',
  NO_GESTURE: 'font-access-no-gesture',
  TOO_MANY: 'font-access-too-many',
  BAD_NAME: 'font-access-bad-name',
  PRIVATE_FONT: 'font-access-private-font',
};

const MAX_FONTS = 256;
const NAME_PATTERN = /^[A-Za-z0-9 ._-]{1,64}$/;
const PRIVATE_HINTS = ['-personal', 'private', 'user-installed'];

function evaluateFontAccess(request, options) {
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
  const fonts = Array.isArray(req.fonts) ? req.fonts : [];
  if (fonts.length > MAX_FONTS) {
    return { ok: false, blocked: true, reason: REASON.TOO_MANY, count: fonts.length, limit: MAX_FONTS };
  }
  for (const font of fonts) {
    const family = String((font && font.family) || '');
    const postscript = String((font && font.postscriptName) || '');
    const name = postscript || family;
    if (!NAME_PATTERN.test(name)) {
      return { ok: false, blocked: true, reason: REASON.BAD_NAME, name: name.slice(0, 48) };
    }
    const lower = name.toLowerCase();
    if (opts.allowLocal === false && PRIVATE_HINTS.some((hint) => lower.includes(hint))) {
      return { ok: false, blocked: true, reason: REASON.PRIVATE_FONT, name: lower.slice(0, 48) };
    }
  }
  return { ok: true, blocked: false, reason: REASON.OK, origin, fonts: fonts.length };
}

function publicList(fonts) {
  const list = Array.isArray(fonts) ? fonts : [];
  return list
    .map((font) => ({ family: String((font && font.family) || '').replace(/[\u0000-\u001f]/g, ''), postscriptName: '' }))
    .filter((font) => font.family !== '');
}

module.exports = {
  REASON,
  MAX_FONTS,
  evaluateFontAccess,
  publicList,
};
