'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'cache-key-empty',
  HOST_IN_KEY: 'cache-key-host',
  FORWARDED_HOST: 'cache-key-forwarded-host',
  UNKEYED_QUERY: 'cache-key-unkeyed-query',
  COOKIE_IN_SHARED: 'cache-key-cookie-shared',
  OVER_LIMIT: 'cache-key-over-limit',
};

const UNSAFE_QUERY = ['utm_source', 'utm_campaign', 'gclid', 'fbclid', 'ref', 'callback'];

function evaluateCacheKey(request, options) {
  const opts = options || {};
  const req = request || {};
  const url = typeof req.url === 'string' ? req.url.trim() : '';
  if (url === '') {
    return { ok: false, blocked: true, reason: REASON.EMPTY, findings: [] };
  }
  let parsed;
  try {
    parsed = new URL(url, 'https://cache.invalid/');
  } catch (err) {
    return { ok: false, blocked: true, reason: REASON.HOST_IN_KEY, findings: [{ reason: REASON.HOST_IN_KEY }] };
  }
  const findings = [];
  const headers = Array.isArray(req.headers) ? req.headers : [];
  for (const entry of headers) {
    if (!Array.isArray(entry)) continue;
    const name = String(entry[0] || '').toLowerCase();
    if (name === 'x-forwarded-host' || name === 'x-original-url' || name === 'x-rewrite-url') {
      findings.push({ reason: REASON.FORWARDED_HOST, header: name });
    }
  }
  if (opts.hostInKey === true) findings.push({ reason: REASON.HOST_IN_KEY, host: parsed.host });
  const query = parsed.search.slice(1);
  if (query !== '') {
    for (const pair of query.split('&')) {
      const name = (pair.split('=')[0] || '').toLowerCase();
      if (UNSAFE_QUERY.includes(name)) findings.push({ reason: REASON.UNKEYED_QUERY, param: name });
    }
  }
  if (opts.sharedCache === true && opts.cookieInKey !== true && parsed.pathname !== '') {
    const hasCookieHeader = headers.some((entry) => Array.isArray(entry) && String(entry[0] || '').toLowerCase() === 'cookie');
    if (hasCookieHeader) findings.push({ reason: REASON.COOKIE_IN_SHARED, path: parsed.pathname.slice(0, 48) });
  }
  if (typeof opts.maxKeyBytes === 'number' && url.length > opts.maxKeyBytes) {
    findings.push({ reason: REASON.OVER_LIMIT, size: url.length, limit: opts.maxKeyBytes });
  }
  if (findings.length > 0) {
    const blocked = findings.some((f) => f.reason === REASON.FORWARDED_HOST);
    return { ok: false, blocked, reason: findings[0].reason, findings };
  }
  return { ok: true, blocked: false, reason: REASON.OK, findings: [] };
}

function canonicalKey(request) {
  const req = request || {};
  const url = typeof req.url === 'string' ? req.url : '';
  let parsed;
  try {
    parsed = new URL(url, 'https://cache.invalid/');
  } catch (err) {
    return '';
  }
  const sorted = parsed.searchParams.toString();
  const path = parsed.pathname.replace(/\/{2,}/g, '/');
  return path + (sorted === '' ? '' : '?' + sorted);
}

module.exports = {
  REASON,
  UNSAFE_QUERY,
  evaluateCacheKey,
  canonicalKey,
};
