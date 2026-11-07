'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'percent-empty',
  BAD_ESCAPE: 'percent-bad-escape',
  DOUBLE_ENCODED: 'percent-double-encoded',
  ENCODED_SEPARATOR: 'percent-encoded-separator',
  ENCODED_DOT: 'percent-encoded-dot',
  OVERLONG_UTF8: 'percent-overlong-utf8',
};

const SEPARATORS = ['%2f', '%5c', '%00', '%3b', '%23', '%3f'];

function evaluatePercentEncoding(url, options) {
  const opts = options || {};
  const text = typeof url === 'string' ? url : '';
  if (text.trim() === '') return { ok: false, blocked: true, reason: REASON.EMPTY };
  const lower = text.toLowerCase();
  let badEscapes = 0;
  for (let i = 0; i < text.length; i += 1) {
    if (text[i] !== '%') continue;
    const hex = text.slice(i + 1, i + 3);
    if (!/^[0-9a-fA-F]{2}$/.test(hex)) badEscapes += 1;
  }
  if (badEscapes > 0) {
    return { ok: false, blocked: true, reason: REASON.BAD_ESCAPE, count: badEscapes };
  }
  if (lower.includes('%25')) {
    const decodedOnce = decodeSafe(text);
    if (decodedOnce.includes('%')) {
      return { ok: false, blocked: true, reason: REASON.DOUBLE_ENCODED, sample: text.slice(0, 64) };
    }
  }
  for (const seq of SEPARATORS) {
    if (lower.includes(seq)) {
      return { ok: false, blocked: true, reason: REASON.ENCODED_SEPARATOR, sequence: seq };
    }
  }
  if (lower.includes('%2e') || lower.includes('%c0%ae')) {
    return { ok: false, blocked: true, reason: REASON.ENCODED_DOT, sample: text.slice(0, 64) };
  }
  if (/(%c0%af|%e0%80%af|%f0%80%80%af)/.test(lower)) {
    return { ok: false, blocked: true, reason: REASON.OVERLONG_UTF8, sample: text.slice(0, 64) };
  }
  if (opts.maxBytes && text.length > opts.maxBytes) {
    return { ok: false, blocked: true, reason: REASON.OVERLONG_UTF8, size: text.length };
  }
  return { ok: true, blocked: false, reason: REASON.OK, escapes: (text.match(/%/g) || []).length };
}

function decodeSafe(text) {
  try {
    return decodeURIComponent(text.replace(/\\+/g, ' '));
  } catch (err) {
    return '';
  }
}

function canonicalize(text) {
  const value = typeof text === 'string' ? text : '';
  if (value === '') return '';
  return value
    .split('/')
    .map((segment) => {
      const decoded = decodeSafe(segment);
      return decoded === '' ? segment : encodeURIComponent(decoded).replace(/%2F/gi, '/');
    })
    .join('/');
}

module.exports = {
  REASON,
  SEPARATORS,
  evaluatePercentEncoding,
  canonicalize,
};
