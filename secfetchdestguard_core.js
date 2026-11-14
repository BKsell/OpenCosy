'use strict';
const { applySecFetchGuard } = require('./secfetchguard_core');

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
const SPEC = {
  header: HEADER,
  allowed: ALLOWED,
  ok: REASON.OK,
  missing: REASON.MISSING,
  duplicate: REASON.DUPLICATE,
  empty: REASON.BAD_VALUE,
  reject: REASON.UNKNOWN,
};

function applySecFetchDestGuard(headers) {
  return applySecFetchGuard(headers, SPEC);
}

module.exports = { REASON, applySecFetchDestGuard };
