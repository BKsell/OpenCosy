'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  WILDCARD_CREDENTIALS: 'wildcard-credentials',
  BAD_VALUE: 'bad-value',
};

const ORIGIN_HEADER = 'access-control-allow-origin';
const CREDENTIALS_HEADER = 'access-control-allow-credentials';

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function textValue(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return '';
  const raw = headers[key];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === 'string' ? value.trim() : '';
}

function applyAcacGuard(headers) {
  const credKey = headerKey(headers, CREDENTIALS_HEADER);
  if (!credKey) {
    const origin = textValue(headers, ORIGIN_HEADER);
    if (origin && origin !== '*') return { changed: false, reason: REASON.MISSING };
    return { changed: false, reason: REASON.MISSING };
  }
  const rawCredentials = headers[credKey];
  const credentials = Array.isArray(rawCredentials) ? rawCredentials.join(',') : rawCredentials;
  if (typeof credentials !== 'string' || credentials.trim().toLowerCase() !== 'true') {
    delete headers[credKey];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  const origin = textValue(headers, ORIGIN_HEADER);
  if (origin === '*') {
    delete headers[credKey];
    return { changed: true, reason: REASON.WILDCARD_CREDENTIALS };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyAcacGuard };
