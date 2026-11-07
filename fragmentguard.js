'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'fragment-empty',
  SECRET_IN_FRAGMENT: 'fragment-secret',
  REFERER_LEAK: 'fragment-referer-leak',
  OVERSIZED: 'fragment-oversized',
  INVALID: 'fragment-invalid',
};

const SECRET_KEYS = ['access_token', 'id_token', 'token', 'password', 'secret', 'code'];

function evaluateFragment(url, options) {
  const opts = options || {};
  const text = typeof url === 'string' ? url.trim() : '';
  if (text === '') return { ok: false, blocked: true, reason: REASON.EMPTY };
  let parsed;
  try {
    parsed = new URL(text, opts.baseUrl || 'https://app.invalid/');
  } catch (err) {
    return { ok: false, blocked: true, reason: REASON.INVALID, url: text.slice(0, 48) };
  }
  const hash = parsed.hash.replace(/^#/, '');
  if (hash === '') return { ok: true, blocked: false, reason: REASON.EMPTY, length: 0 };
  if (hash.length > (opts.maxBytes || 1024)) {
    return { ok: false, blocked: true, reason: REASON.OVERSIZED, size: hash.length };
  }
  if (opts.stripForReferer === true) {
    return { ok: false, blocked: false, reason: REASON.REFERER_LEAK, suggest: stripFragment(text), size: hash.length };
  }
  for (const pair of hash.split('&')) {
    const name = (pair.split('=')[0] || '').toLowerCase();
    if (SECRET_KEYS.includes(name)) {
      return { ok: false, blocked: true, reason: REASON.SECRET_IN_FRAGMENT, key: name };
    }
  }
  return { ok: true, blocked: false, reason: REASON.OK, length: hash.length };
}

function stripFragment(url) {
  const text = typeof url === 'string' ? url : '';
  const idx = text.indexOf('#');
  if (idx === -1) return text;
  return text.slice(0, idx);
}

module.exports = {
  REASON,
  SECRET_KEYS,
  evaluateFragment,
  stripFragment,
};
