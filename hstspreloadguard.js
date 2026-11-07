'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'hsts-empty',
  MAX_AGE_LOW: 'hsts-max-age-low',
  NO_SUBDOMAINS: 'hsts-no-subdomains',
  NO_PRELOAD: 'hsts-no-preload',
  DUPLICATE: 'hsts-duplicate',
  MALFORMED: 'hsts-malformed',
};

const MIN_MAX_AGE = 31536000;

function evaluateHsts(header, options) {
  const opts = options || {};
  if (typeof header !== 'string' || header.trim() === '') {
    return { ok: false, blocked: true, reason: REASON.EMPTY, maxAge: 0 };
  }
  if (header.includes(',')) {
    return { ok: false, blocked: true, reason: REASON.DUPLICATE, raw: header.slice(0, 96) };
  }
  const directives = header.split(';').map((d) => d.trim()).filter((d) => d !== '');
  let maxAge = null;
  let includeSubDomains = false;
  let preload = false;
  for (const directive of directives) {
    const eq = directive.indexOf('=');
    if (eq === -1) {
      const name = directive.toLowerCase();
      if (name === 'includesubdomains') includeSubDomains = true;
      else if (name === 'preload') preload = true;
      else return { ok: false, blocked: true, reason: REASON.MALFORMED, raw: directive.slice(0, 48) };
      continue;
    }
    const name = directive.slice(0, eq).trim().toLowerCase();
    const value = directive.slice(eq + 1).trim().replace(/^"|"$/g, '');
    if (name !== 'max-age') {
      return { ok: false, blocked: true, reason: REASON.MALFORMED, raw: directive.slice(0, 48) };
    }
    if (!/^\d+$/.test(value)) {
      return { ok: false, blocked: true, reason: REASON.MALFORMED, raw: directive.slice(0, 48) };
    }
    maxAge = Number(value);
  }
  if (maxAge === null) {
    return { ok: false, blocked: true, reason: REASON.MALFORMED, raw: header.slice(0, 96) };
  }
  if (maxAge < MIN_MAX_AGE) {
    return { ok: false, blocked: true, reason: REASON.MAX_AGE_LOW, maxAge, required: MIN_MAX_AGE };
  }
  if (opts.requireSubDomains === true && !includeSubDomains) {
    return { ok: false, blocked: true, reason: REASON.NO_SUBDOMAINS, maxAge };
  }
  if (opts.requirePreload === true && !preload) {
    return { ok: false, blocked: true, reason: REASON.NO_PRELOAD, maxAge };
  }
  return { ok: true, blocked: false, reason: REASON.OK, maxAge, includeSubDomains, preload };
}

function describeFinding(result) {
  if (!result || result.ok) return 'hsts policy accepted';
  return result.reason + ' (maxAge=' + String(result.maxAge === undefined ? 'n/a' : result.maxAge) + ')';
}

module.exports = {
  REASON,
  MIN_MAX_AGE,
  evaluateHsts,
  describeFinding,
};
