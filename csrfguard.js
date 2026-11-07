'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'csrf-empty',
  SAFE_METHOD: 'csrf-safe-method',
  NO_ORIGIN: 'csrf-no-origin',
  CROSS_ORIGIN: 'csrf-cross-origin',
  NULL_ORIGIN: 'csrf-null-origin',
  SEC_FETCH_SITE: 'csrf-sec-fetch-site',
};

const STATE_CHANGING = ['POST', 'PUT', 'PATCH', 'DELETE'];
const SAFE = ['GET', 'HEAD', 'OPTIONS'];

function headerValue(headers, name) {
  const list = Array.isArray(headers) ? headers : [];
  for (const entry of list) {
    if (!Array.isArray(entry)) continue;
    if (String(entry[0] || '').toLowerCase() === name) return String(entry[1] || '');
  }
  return null;
}

function evaluateCsrf(request) {
  const req = request || {};
  const method = String(req.method || 'GET').toUpperCase();
  if (SAFE.includes(method)) {
    return { ok: true, blocked: false, reason: REASON.SAFE_METHOD, method };
  }
  if (!STATE_CHANGING.includes(method)) {
    return { ok: false, blocked: true, reason: REASON.SAFE_METHOD, method };
  }
  const headers = Array.isArray(req.headers) ? req.headers : [];
  const origin = headerValue(headers, 'origin');
  const referer = headerValue(headers, 'referer');
  const fetchSite = headerValue(headers, 'sec-fetch-site');
  const expected = String(req.expectedOrigin || '').toLowerCase();
  if (fetchSite !== null && fetchSite.trim().toLowerCase() === 'cross-site') {
    return { ok: false, blocked: true, reason: REASON.SEC_FETCH_SITE, method, fetchSite };
  }
  if (origin !== null) {
    const value = origin.trim().toLowerCase();
    if (value === 'null') return { ok: false, blocked: true, reason: REASON.NULL_ORIGIN, method };
    if (expected !== '' && value !== expected && expected !== '*') {
      return { ok: false, blocked: true, reason: REASON.CROSS_ORIGIN, method, origin: value, expected };
    }
    return { ok: true, blocked: false, reason: REASON.OK, method, source: 'origin' };
  }
  if (referer !== null) {
    let host = '';
    try {
      host = new URL(referer).origin.toLowerCase();
    } catch (err) {
      return { ok: false, blocked: true, reason: REASON.CROSS_ORIGIN, method, origin: 'invalid-referer' };
    }
    if (expected !== '' && host !== expected && expected !== '*') {
      return { ok: false, blocked: true, reason: REASON.CROSS_ORIGIN, method, origin: host, expected };
    }
    return { ok: true, blocked: false, reason: REASON.OK, method, source: 'referer' };
  }
  return { ok: false, blocked: true, reason: REASON.NO_ORIGIN, method };
}

module.exports = {
  REASON,
  STATE_CHANGING,
  SAFE,
  evaluateCsrf,
};
