'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  DUPLICATE: 'duplicate',
};

const HEADER = 'x-content-type-options';
const MAX_LENGTH = 128;

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function applyNoSniffGuard(headers) {
  const key = headerKey(headers, HEADER);
  if (!key) return { changed: false, reason: REASON.MISSING };
  const raw = headers[key];
  const value = Array.isArray(raw) ? raw.join(',') : raw;
  if (typeof value !== 'string') {
    headers[key] = 'nosniff';
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  const text = value.trim().toLowerCase();
  if (!text || text.length > MAX_LENGTH) {
    headers[key] = 'nosniff';
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (text.includes(',')) {
    headers[key] = 'nosniff';
    return { changed: true, reason: REASON.DUPLICATE };
  }
  if (text !== 'nosniff') {
    headers[key] = 'nosniff';
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyNoSniffGuard };
