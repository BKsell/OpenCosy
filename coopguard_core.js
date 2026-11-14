'use strict';
const { singleAlt } = require('./modutil_core');
const tokenOf = singleAlt;

const { headerKey, rawValue } = require('./headerutil_core');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  DUPLICATE: 'duplicate',
};

const HEADER = 'cross-origin-opener-policy';
const ALLOWED = new Set(['same-origin', 'same-origin-allow-popups', 'unsafe-none']);
const SAFE_DEFAULT = 'same-origin';

function applyCoopGuard(headers) {
  const raw = rawValue(headers, HEADER);
  if (raw === null) return { changed: false, reason: REASON.MISSING };
  const key = headerKey(headers, HEADER);
  const value = tokenOf(raw);
  if (value === null) {
    headers[key] = SAFE_DEFAULT;
    return { changed: true, reason: REASON.DUPLICATE };
  }
  if (value === '') {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (!ALLOWED.has(value)) {
    headers[key] = SAFE_DEFAULT;
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyCoopGuard };
