'use strict';
const { rawValue } = require('./headerutil_core');
const { singleAlt } = require('./modutil_core');
const single = singleAlt;

const { headerKey } = require('./headerutil_core');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  UNSAFE_METHOD: 'unsafe-method',
  TOO_LONG: 'too-long',
  DUPLICATE: 'duplicate',
};

const HEADER = 'x-http-method-override';
const ALLOWED = new Set(['DELETE', 'PATCH', 'PUT']);
const TOKEN = /^[A-Za-z]{1,16}$/;
const MAX_LENGTH = 16;

function applyXHttpMethodOverrideGuard(headers) {
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
  if (value.length > MAX_LENGTH) {
    delete headers[key];
    return { changed: true, reason: REASON.TOO_LONG };
  }
  if (!TOKEN.test(value)) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  const method = value.toUpperCase();
  if (!ALLOWED.has(method)) {
    delete headers[key];
    return { changed: true, reason: REASON.UNSAFE_METHOD };
  }
  if (method !== value) {
    headers[key] = method;
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyXHttpMethodOverrideGuard };
