'use strict';

const MAX_URL_CHARS = 8192;
const ALLOWED_PROTOCOLS = Object.freeze(['http:', 'https:']);

function sanitizeWebUrl(rawUrl, reasons, limit) {
  const table = reasons || {};
  const cap = typeof limit === 'number' && limit > 0 ? limit : MAX_URL_CHARS;
  if (typeof rawUrl !== 'string' || rawUrl.length === 0) {
    return { ok: false, url: '', reason: table.empty };
  }
  if (rawUrl.length > cap) {
    return { ok: false, url: '', reason: table.tooLong };
  }
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    return { ok: false, url: '', reason: table.badUrl };
  }
  if (!ALLOWED_PROTOCOLS.includes(u.protocol)) {
    return { ok: false, url: '', reason: table.badProtocol };
  }
  if (!u.hostname) {
    return { ok: false, url: '', reason: table.badUrl };
  }
  if (u.username || u.password) {
    return { ok: false, url: '', reason: table.credentials || table.badUrl };
  }
  return { ok: true, url: u.href, reason: '' };
}

module.exports = {
  MAX_URL_CHARS,
  ALLOWED_PROTOCOLS,
  sanitizeWebUrl,
};
