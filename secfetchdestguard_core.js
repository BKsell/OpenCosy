'use strict';
const { singleAlt } = require('./modutil_core');
const single = singleAlt;

const { headerKey, rawValue } = require('./headerutil_core');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  DUPLICATE: 'duplicate',
  UNKNOWN: 'unknown-destination',
};

const HEADER = 'sec-fetch-dest';
const ALLOWED = new Set([
  'audio', 'audioworklet', 'document', 'embed', 'empty', 'font', 'frame',
  'iframe', 'image', 'manifest', 'object', 'paintworklet', 'report', 'script',
  'sharedworker', 'style', 'track', 'video', 'worker', 'xslt',
]);

function applySecFetchDestGuard(headers) {
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
    return { changed: true, reason: REASON.UNKNOWN };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applySecFetchDestGuard };
