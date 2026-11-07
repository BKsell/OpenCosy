'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  WILDCARD: 'wildcard',
  TOO_MANY: 'too-many',
};

const HEADER = 'timing-allow-origin';
const MAX_ORIGINS = 8;
const ORIGIN = /^https:\/\/[A-Za-z0-9.-]{1,253}(:\d{1,5})?$/;

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

function applyTimingAllowOriginGuard(headers) {
  const raw = rawValue(headers, HEADER);
  if (raw === null) return { changed: false, reason: REASON.MISSING };
  const key = headerKey(headers, HEADER);
  const text = Array.isArray(raw) ? raw.map((v) => String(v)).join(',') : String(raw);
  if (/[\u0000-\u0008\u000a-\u001f\u007f]/.test(text)) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  const origins = text.split(',').map((v) => v.trim()).filter(Boolean);
  if (origins.length === 0) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (origins.length > MAX_ORIGINS) {
    headers[key] = origins.slice(0, MAX_ORIGINS).join(', ');
    return { changed: true, reason: REASON.TOO_MANY };
  }
  let reason = REASON.OK;
  const safe = [];
  for (const origin of origins) {
    if (origin === '*') {
      reason = REASON.WILDCARD;
      continue;
    }
    if (!ORIGIN.test(origin)) {
      reason = REASON.BAD_VALUE;
      continue;
    }
    safe.push(origin);
  }
  if (safe.length === 0) {
    delete headers[key];
    return { changed: true, reason: reason === REASON.OK ? REASON.BAD_VALUE : reason };
  }
  if (reason !== REASON.OK) {
    headers[key] = safe.join(', ');
    return { changed: true, reason };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyTimingAllowOriginGuard };
