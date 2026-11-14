'use strict';
const { singleAlt } = require('./modutil_core');
const single = singleAlt;

const { headerKey, rawValue } = require('./headerutil_core');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  DUPLICATE: 'duplicate',
  WEAK: 'weak-policy',
};

const HEADER = 'cross-origin-resource-policy';
const ALLOWED = new Set(['same-site', 'same-origin']);
const LEGACY_SAME_ORIGIN = 'same-origin';

function applyCorpGuard(headers) {
  const raw = rawValue(headers, HEADER);
  if (raw === null) return { changed: false, reason: REASON.MISSING };
  const key = headerKey(headers, HEADER);
  const value = single(raw);
  if (value === null) {
    headers[key] = LEGACY_SAME_ORIGIN;
    return { changed: true, reason: REASON.DUPLICATE };
  }
  if (value === '') {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (value === 'cross-origin') {
    headers[key] = LEGACY_SAME_ORIGIN;
    return { changed: true, reason: REASON.WEAK };
  }
  if (!ALLOWED.has(value)) {
    headers[key] = LEGACY_SAME_ORIGIN;
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyCorpGuard };
