'use strict';

const { firstText, headerKey } = require('./headerutil_core');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  WILDCARD_CREDENTIALS: 'wildcard-credentials',
  BAD_VALUE: 'bad-value',
};

const ORIGIN_HEADER = 'access-control-allow-origin';
const CREDENTIALS_HEADER = 'access-control-allow-credentials';

function applyAcacGuard(headers) {
  const credKey = headerKey(headers, CREDENTIALS_HEADER);
  if (!credKey) {
    const origin = firstText(headers, ORIGIN_HEADER);
    if (origin && origin !== '*') return { changed: false, reason: REASON.MISSING };
    return { changed: false, reason: REASON.MISSING };
  }
  const rawCredentials = headers[credKey];
  const credentials = Array.isArray(rawCredentials) ? rawCredentials.join(',') : rawCredentials;
  if (typeof credentials !== 'string' || credentials.trim().toLowerCase() !== 'true') {
    delete headers[credKey];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  const origin = firstText(headers, ORIGIN_HEADER);
  if (origin === '*') {
    delete headers[credKey];
    return { changed: true, reason: REASON.WILDCARD_CREDENTIALS };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyAcacGuard };
