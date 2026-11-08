'use strict';
const { singleAlt } = require('./modutil');
const single = singleAlt;

const { headerKey, rawValue } = require('./headerutil');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  DUPLICATE: 'duplicate',
  UNSAFE: 'unsafe',
};

const HEADER = 'sec-fetch-mode';
const ALLOWED = new Set(['cors', 'no-cors', 'navigate', 'same-origin', 'websocket']);

function applySecFetchModeGuard(headers) {
  const raw = rawValue(headers, HEADER);
  if (raw === null) return { changed: false, reason: REASON.MISSING };
  const key = headerKey(headers, HEADER);
  const value = single(raw);
  if (value === null) {
    delete headers[key];
    return { changed: true, reason: REASON.DUPLICATE };
  }
  if (value === '') {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (!ALLOWED.has(value)) {
    delete headers[key];
    return { changed: true, reason: REASON.UNSAFE };
  }
  if (value !== String(Array.isArray(raw) ? raw[0] : raw).trim()) {
    headers[key] = value;
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applySecFetchModeGuard };
