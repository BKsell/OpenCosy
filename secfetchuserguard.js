'use strict';
const { rawValue } = require('./headerutil');
const { singleAlt } = require('./modutil');
const single = singleAlt;

const { headerKey } = require('./headerutil');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  DUPLICATE: 'duplicate',
};

const HEADER = 'sec-fetch-user';
const ALLOWED = new Set(['?0', '?1']);

function applySecFetchUserGuard(headers) {
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
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applySecFetchUserGuard };
