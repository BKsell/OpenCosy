'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'vary-empty',
  WILDCARD: 'vary-wildcard',
  MISSING_ACCEPT_ENCODING: 'vary-missing-accept-encoding',
  MISSING_LANGUAGE: 'vary-missing-language',
  MISSING_COOKIE: 'vary-missing-cookie',
  MALFORMED: 'vary-malformed',
};

const NEGOTIATED = {
  'accept-encoding': 'accept-encoding',
  'accept-language': 'accept-language',
  cookie: 'cookie',
};

function evaluateVary(headers, options) {
  const opts = options || {};
  const list = Array.isArray(headers) ? headers : [];
  if (list.length === 0) {
    return { ok: false, blocked: true, reason: REASON.EMPTY, vary: [] };
  }
  let vary = [];
  for (const entry of list) {
    if (!Array.isArray(entry)) continue;
    if (String(entry[0] || '').toLowerCase() !== 'vary') continue;
    const raw = String(entry[1] || '');
    for (const part of raw.split(',')) {
      const token = part.trim().toLowerCase();
      if (token !== '') vary.push(token);
    }
  }
  if (vary.includes('*')) {
    return { ok: false, blocked: true, reason: REASON.WILDCARD, vary };
  }
  if (vary.some((token) => token.includes(' ') || token.includes(';'))) {
    return { ok: false, blocked: true, reason: REASON.MALFORMED, vary: vary.slice(0, 4) };
  }
  const required = ['accept-encoding'];
  if (opts.contentLanguage === true) required.push('accept-language');
  if (opts.personalized === true) required.push('cookie');
  for (const token of required) {
    if (!vary.includes(token)) {
      const reason = token === 'accept-language'
        ? REASON.MISSING_LANGUAGE
        : token === 'cookie'
          ? REASON.MISSING_COOKIE
          : REASON.MISSING_ACCEPT_ENCODING;
      return { ok: false, blocked: false, reason, missing: token, vary };
    }
  }
  return { ok: true, blocked: false, reason: REASON.OK, vary };
}

function varyKey(vary) {
  const list = Array.isArray(vary) ? vary : [];
  if (list.length === 0) return '';
  return list.slice().sort().join(',');
}

module.exports = {
  REASON,
  NEGOTIATED,
  evaluateVary,
  varyKey,
};
