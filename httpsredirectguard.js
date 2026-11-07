'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'https-redirect-empty',
  ALREADY_SECURE: 'https-redirect-already-secure',
  DOWNGRADE: 'https-redirect-downgrade',
  NO_PATH_SAFE: 'https-redirect-unsafe-location',
  CREDENTIALS: 'https-redirect-credentials',
  LOOP: 'https-redirect-loop',
};

function evaluateHttpsRedirect(request, options) {
  const opts = options || {};
  const req = request || {};
  const url = typeof req.url === 'string' ? req.url.trim() : '';
  if (url === '') return { ok: false, blocked: true, reason: REASON.EMPTY };
  let parsed;
  try {
    parsed = new URL(url, 'https://app.invalid/');
  } catch (err) {
    return { ok: false, blocked: true, reason: REASON.EMPTY, url: url.slice(0, 48) };
  }
  if (parsed.protocol === 'https:') {
    return { ok: true, blocked: false, reason: REASON.ALREADY_SECURE, origin: parsed.origin };
  }
  if (parsed.protocol !== 'http:') {
    return { ok: false, blocked: true, reason: REASON.DOWNGRADE, protocol: parsed.protocol };
  }
  const target = 'https://' + parsed.host + parsed.pathname + parsed.search;
  if (req.location && String(req.location).startsWith('http://')) {
    return { ok: false, blocked: true, reason: REASON.DOWNGRADE, target };
  }
  if (req.location && String(req.location).includes('@')) {
    return { ok: false, blocked: true, reason: REASON.CREDENTIALS, target };
  }
  if (req.location && String(req.location).includes('\\')) {
    return { ok: false, blocked: true, reason: REASON.NO_PATH_SAFE, target };
  }
  if (req.hops !== undefined && Number(req.hops) >= (opts.maxHops || 5)) {
    return { ok: false, blocked: true, reason: REASON.LOOP, hops: Number(req.hops) };
  }
  return { ok: true, blocked: false, reason: REASON.OK, target, origin: parsed.origin };
}

function statusCode(options) {
  const opts = options || {};
  return opts.permanent === true ? 308 : 307;
}

module.exports = {
  REASON,
  evaluateHttpsRedirect,
  statusCode,
};
