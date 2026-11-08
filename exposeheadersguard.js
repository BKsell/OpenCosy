'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  TOO_MANY: 'too-many',
  WILDCARD: 'wildcard',
};

const HEADER = 'access-control-expose-headers';
const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const MAX_ENTRIES = 32;

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

function splitList(raw) {
  if (Array.isArray(raw)) return raw.map((v) => String(v)).join(',').split(',');
  if (typeof raw !== 'string') return [];
  return raw.split(',');
}

function applyExposeHeadersGuard(headers, options) {
  const raw = rawValue(headers, HEADER);
  if (raw === null) return { changed: false, reason: REASON.MISSING };
  const key = headerKey(headers, HEADER);
  const entries = splitList(raw).map((v) => v.trim()).filter(Boolean);
  if (entries.length === 0) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (entries.length > MAX_ENTRIES) {
    headers[key] = entries.slice(0, MAX_ENTRIES).join(', ');
    return { changed: true, reason: REASON.TOO_MANY };
  }
  const credentials = options && options.credentials === true;
  let reason = REASON.OK;
  const seen = new Set();
  const safe = [];
  for (const entry of entries) {
    const lower = entry.toLowerCase();
    if (lower === '*') {
      if (credentials) {
        reason = REASON.WILDCARD;
        continue;
      }
      safe.push(entry);
      continue;
    }
    if (!TOKEN.test(entry)) {
      reason = REASON.BAD_VALUE;
      continue;
    }
    if (seen.has(lower)) {
      reason = REASON.DUPLICATE;
      continue;
    }
    seen.add(lower);
    safe.push(entry);
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

module.exports = { REASON, applyExposeHeadersGuard };
