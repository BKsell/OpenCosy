'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  NEGATIVE: 'negative',
  TOO_LARGE: 'too-large',
};

const HEADER = 'access-control-max-age';
const MAX_SECONDS = 86400;
const DEFAULT_SECONDS = 600;

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
  if (Array.isArray(raw)) return raw.length === 1 ? String(raw[0]).trim() : null;
  if (typeof raw !== 'string') return null;
  return raw.trim();
}

function applyMaxAgeGuard(headers) {
  const raw = rawValue(headers, HEADER);
  if (raw === null) return { changed: false, reason: REASON.MISSING };
  const key = headerKey(headers, HEADER);
  const value = single(raw);
  if (value === null) {
    headers[key] = String(DEFAULT_SECONDS);
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (value === '') {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (!/^-?\d+$/.test(value)) {
    headers[key] = String(DEFAULT_SECONDS);
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  const seconds = Number(value);
  if (seconds < 0) {
    headers[key] = '0';
    return { changed: true, reason: REASON.NEGATIVE };
  }
  if (seconds > MAX_SECONDS) {
    headers[key] = String(MAX_SECONDS);
    return { changed: true, reason: REASON.TOO_LARGE };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyMaxAgeGuard };
