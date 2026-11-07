'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'prefetch-empty',
  PLAINTEXT: 'prefetch-plaintext',
  CREDENTIALS: 'prefetch-credentials',
  CROSS_SITE: 'prefetch-cross-site',
  SECRET_QUERY: 'prefetch-secret-query',
  MISSING_PURPOSE: 'prefetch-missing-purpose',
};

const SECRET_PARAMS = ['token', 'access_token', 'session', 'password', 'key', 'signature'];
const ALLOWED_PURPOSE = ['prefetch', 'preload', 'prerender'];

function evaluatePrefetch(request, options) {
  const opts = options || {};
  const req = request || {};
  const url = typeof req.url === 'string' ? req.url.trim() : '';
  if (url === '') return { ok: false, blocked: true, reason: REASON.EMPTY };
  let parsed;
  try {
    parsed = new URL(url, opts.baseUrl || 'https://app.invalid/');
  } catch (err) {
    return { ok: false, blocked: true, reason: REASON.EMPTY, url: url.slice(0, 48) };
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return { ok: false, blocked: true, reason: REASON.PLAINTEXT, protocol: parsed.protocol };
  }
  if (parsed.protocol === 'http:' && opts.allowHttp !== true) {
    return { ok: false, blocked: true, reason: REASON.PLAINTEXT, protocol: parsed.protocol };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, blocked: true, reason: REASON.CREDENTIALS, origin: parsed.origin };
  }
  for (const pair of parsed.search.replace(/^\?/, '').split('&')) {
    const name = (pair.split('=')[0] || '').toLowerCase();
    if (SECRET_PARAMS.includes(name)) {
      return { ok: false, blocked: true, reason: REASON.SECRET_QUERY, param: name, path: parsed.pathname.slice(0, 48) };
    }
  }
  const purpose = String(req.purpose || '').toLowerCase();
  if (purpose !== '' && !ALLOWED_PURPOSE.includes(purpose)) {
    return { ok: false, blocked: true, reason: REASON.MISSING_PURPOSE, purpose: purpose.slice(0, 24) };
  }
  if (purpose === '' && opts.requirePurpose === true) {
    return { ok: false, blocked: true, reason: REASON.MISSING_PURPOSE };
  }
  if (opts.sameSite !== false && opts.siteOrigin) {
    const siteOrigin = String(opts.siteOrigin).toLowerCase();
    if (parsed.origin.toLowerCase() !== siteOrigin) {
      return { ok: false, blocked: true, reason: REASON.CROSS_SITE, origin: parsed.origin, site: siteOrigin };
    }
  }
  return { ok: true, blocked: false, reason: REASON.OK, origin: parsed.origin, path: parsed.pathname };
}

function dedupe(list) {
  const items = Array.isArray(list) ? list : [];
  const seen = new Set();
  const out = [];
  for (const item of items) {
    const key = String(item && item.url ? item.url : item);
    if (key === '' || seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}

module.exports = {
  REASON,
  SECRET_PARAMS,
  ALLOWED_PURPOSE,
  evaluatePrefetch,
  dedupe,
};
