'use strict';
const { applySecFetchGuard } = require('./secfetchguard_core');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  DUPLICATE: 'duplicate',
  UNSAFE: 'unsafe',
};

const HEADER = 'sec-fetch-mode';
const ALLOWED = new Set(['cors', 'no-cors', 'navigate', 'same-origin', 'websocket']);
const SPEC = {
  header: HEADER,
  allowed: ALLOWED,
  ok: REASON.OK,
  missing: REASON.MISSING,
  duplicate: REASON.DUPLICATE,
  empty: REASON.BAD_VALUE,
  reject: REASON.UNSAFE,
  trimFix: true,
  trimReason: REASON.BAD_VALUE,
};

function applySecFetchModeGuard(headers) {
  return applySecFetchGuard(headers, SPEC);
}

module.exports = { REASON, applySecFetchModeGuard };
