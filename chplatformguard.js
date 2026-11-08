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
  TOO_LONG: 'too-long',
};

const HEADER = 'sec-ch-ua-platform';
const QUOTED = /^"([A-Za-z0-9 _\-().]{1,32})"$/;

function applyChPlatformGuard(headers) {
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
  if (value.length > 64) {
    delete headers[key];
    return { changed: true, reason: REASON.TOO_LONG };
  }
  if (!QUOTED.test(value)) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyChPlatformGuard };
