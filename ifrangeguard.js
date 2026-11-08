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

const HEADER = 'if-range';
const ETAG = /^(W\/)?"[!#$%&'*+.^_`|~0-9A-Za-z:\-]{1,128}"$/;
const IMF = /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/;
const MAX_LENGTH = 96;

function applyIfRangeGuard(headers) {
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
  if (ETAG.test(value)) {
    return { changed: false, reason: REASON.OK };
  }
  if (IMF.test(value)) {
    const time = Date.parse(value);
    if (Number.isFinite(time)) return { changed: false, reason: REASON.OK };
  }
  delete headers[key];
  return { changed: true, reason: REASON.BAD_VALUE };
}

module.exports = { REASON, applyIfRangeGuard };
