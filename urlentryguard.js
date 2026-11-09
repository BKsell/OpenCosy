'use strict';

const MAX_URL_CHARS = 8192;
const ALLOWED_PROTOCOLS = Object.freeze(['http:', 'https:']);

function sanitizeWebUrl(rawUrl, reasons, limit) {
  if (typeof rawUrl !== 'string' || rawUrl.length === 0) {
    return { ok: false, url: '', reason: reasons.empty };
  }
  if (rawUrl.length > limit) {
    return { ok: false, url: '', reason: reasons.tooLong };
  }
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    return { ok: false, url: '', reason: reasons.badUrl };
  }
  if (!ALLOWED_PROTOCOLS.includes(u.protocol)) {
    return { ok: false, url: '', reason: reasons.badProtocol };
  }
  if (!u.hostname) {
    return { ok: false, url: '', reason: reasons.badUrl };
  }
  if (u.username || u.password) {
    return { ok: false, url: '', reason: reasons.credentials || reasons.badUrl };
  }
  return { ok: true, url: u.href, reason: '' };
}

module.exports = {
  MAX_URL_CHARS,
  ALLOWED_PROTOCOLS,
  sanitizeWebUrl,
};
