'use strict';
const { applySecFetchGuard } = require('./secfetchguard_core');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  DUPLICATE: 'duplicate',
};

const HEADER = 'sec-fetch-user';
const ALLOWED = new Set(['?0', '?1']);
const SPEC = {
  header: HEADER,
  allowed: ALLOWED,
  ok: REASON.OK,
  missing: REASON.MISSING,
  duplicate: REASON.DUPLICATE,
  empty: REASON.BAD_VALUE,
  reject: REASON.BAD_VALUE,
};

function applySecFetchUserGuard(headers) {
  return applySecFetchGuard(headers, SPEC);
}

module.exports = { REASON, applySecFetchUserGuard };
