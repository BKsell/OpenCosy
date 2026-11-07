'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'content-length-empty',
  NOT_NUMERIC: 'content-length-not-numeric',
  NEGATIVE: 'content-length-negative',
  NEGATIVE_EXTRA: 'content-length-extra',
  OVER_LIMIT: 'content-length-over-limit',
  MISMATCH: 'content-length-mismatch',
};

const MAX_DEFAULT = 32 * 1024 * 1024;

function evaluateContentLength(header, actualBytes, options) {
  const opts = options || {};
  const limit = typeof opts.limit === 'number' && opts.limit > 0 ? opts.limit : MAX_DEFAULT;
  if (header === undefined || header === null || String(header).trim() === '') {
    return { ok: false, blocked: true, reason: REASON.EMPTY, declared: null };
  }
  const raw = String(header).trim();
  if (raw.includes(',')) {
    return { ok: false, blocked: true, reason: REASON.NEGATIVE_EXTRA, declared: raw.slice(0, 48) };
  }
  if (raw.startsWith('-')) {
    return { ok: false, blocked: true, reason: REASON.NEGATIVE, declared: raw.slice(0, 32) };
  }
  if (!/^[0-9]+$/.test(raw)) {
    return { ok: false, blocked: true, reason: REASON.NOT_NUMERIC, declared: raw.slice(0, 32) };
  }
  const declared = Number(raw);
  if (!Number.isSafeInteger(declared)) {
    return { ok: false, blocked: true, reason: REASON.NOT_NUMERIC, declared: raw.slice(0, 32) };
  }
  if (declared > limit) {
    return { ok: false, blocked: true, reason: REASON.OVER_LIMIT, declared, limit };
  }
  if (typeof actualBytes === 'number' && actualBytes >= 0 && actualBytes !== declared) {
    return { ok: false, blocked: true, reason: REASON.MISMATCH, declared, actual: actualBytes };
  }
  return { ok: true, blocked: false, reason: REASON.OK, declared, limit };
}

function summarize(result) {
  if (!result || result.ok) return 'content length accepted';
  if (result.reason === REASON.OVER_LIMIT) {
    return result.reason + ' (' + String(result.declared) + ' > ' + String(result.limit) + ')';
  }
  if (result.reason === REASON.MISMATCH) {
    return result.reason + ' (' + String(result.declared) + ' vs ' + String(result.actual) + ')';
  }
  return result.reason + ' (' + String(result.declared) + ')';
}

module.exports = {
  REASON,
  MAX_DEFAULT,
  evaluateContentLength,
  summarize,
};
