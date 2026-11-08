'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  DUPLICATE: 'duplicate',
  UNSAFE: 'unsafe',
};

const HEADER = 'sec-fetch-mode';
const ALLOWED = new Set(['cors', 'no-cors', 'navigate', 'same-origin', 'websocket']);

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function rawValue(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return null;
  return headers[key];
}

function single(raw) {
  if (Array.isArray(raw)) {
    if (raw.length !== 1) return null;
    return String(raw[0]).trim().toLowerCase();
  }
  if (typeof raw !== 'string') return null;
  return raw.trim().toLowerCase();
}

function applySecFetchModeGuard(headers) {
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
    return { changed: true, reason: REASON.UNSAFE };
  }
  if (value !== String(Array.isArray(raw) ? raw[0] : raw).trim()) {
    headers[key] = value;
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applySecFetchModeGuard };
