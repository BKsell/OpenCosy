'use strict';

const { headerKey } = require('./headerutil');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  OVERLONG: 'overlong',
};

const HEADER = 'save-data';
const MAX_LENGTH = 16;

function applySaveDataGuard(headers) {
  const key = headerKey(headers, HEADER);
  if (!key) return { changed: false, reason: REASON.MISSING };
  const raw = headers[key];
  const value = Array.isArray(raw) ? raw.join(',') : raw;
  if (typeof value !== 'string') {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  const text = value.trim().toLowerCase();
  if (text.length > MAX_LENGTH) {
    delete headers[key];
    return { changed: true, reason: REASON.OVERLONG };
  }
  if (text !== 'on') {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applySaveDataGuard };
