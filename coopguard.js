'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  DUPLICATE: 'duplicate',
};

const HEADER = 'cross-origin-opener-policy';
const ALLOWED = new Set(['same-origin', 'same-origin-allow-popups', 'unsafe-none']);
const SAFE_DEFAULT = 'same-origin';

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

function tokenOf(raw) {
  if (Array.isArray(raw)) {
    if (raw.length !== 1) return null;
    return String(raw[0]).trim().toLowerCase();
  }
  if (typeof raw !== 'string') return null;
  return raw.trim().toLowerCase();
}

function applyCoopGuard(headers) {
  const raw = rawValue(headers, HEADER);
  if (raw === null) return { changed: false, reason: REASON.MISSING };
  const key = headerKey(headers, HEADER);
  const value = tokenOf(raw);
  if (value === null) {
    headers[key] = SAFE_DEFAULT;
    return { changed: true, reason: REASON.DUPLICATE };
  }
  if (value === '') {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (!ALLOWED.has(value)) {
    headers[key] = SAFE_DEFAULT;
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyCoopGuard };
