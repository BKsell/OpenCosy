'use strict';

const { headerKey } = require('./headerutil_core');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
};

const HEADER = 'dnt';

function applyDntGuard(headers) {
  const key = headerKey(headers, HEADER);
  if (!key) return { changed: false, reason: REASON.MISSING };
  const raw = headers[key];
  const value = Array.isArray(raw) ? raw.join(',') : raw;
  const normalized = typeof value === 'string' ? value.trim() : '';
  if (normalized !== '0' && normalized !== '1') {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyDntGuard };
