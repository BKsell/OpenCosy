'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  TOO_MANY: 'too-many',
  DUPLICATE: 'duplicate',
};

const HEADER = 'critical-ch';
const TOKEN = /^[a-z0-9!#$%&'*+.^_`|~-]{1,64}$/;
const MAX_ENTRIES = 8;

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

function applyCriticalChGuard(headers) {
  const raw = rawValue(headers, HEADER);
  if (raw === null) return { changed: false, reason: REASON.MISSING };
  const key = headerKey(headers, HEADER);
  const text = Array.isArray(raw) ? raw.map((v) => String(v)).join(',') : String(raw);
  const originals = text.split(',').map((v) => v.trim()).filter(Boolean);
  const entries = originals.map((v) => v.toLowerCase());
  if (entries.length === 0) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (entries.length > MAX_ENTRIES) {
    headers[key] = entries.slice(0, MAX_ENTRIES).join(', ');
    return { changed: true, reason: REASON.TOO_MANY };
  }
  let reason = REASON.OK;
  const safe = [];
  const seen = new Set();
  for (const entry of entries) {
    if (!TOKEN.test(entry)) {
      reason = REASON.BAD_VALUE;
      continue;
    }
    if (seen.has(entry)) {
      reason = REASON.DUPLICATE;
      continue;
    }
    seen.add(entry);
    safe.push(entry);
  }
  if (safe.length === 0) {
    delete headers[key];
    return { changed: true, reason: reason === REASON.OK ? REASON.BAD_VALUE : reason };
  }
  const joined = safe.join(', ');
  if (reason !== REASON.OK || joined !== originals.join(', ')) {
    headers[key] = joined;
    return { changed: true, reason: reason === REASON.OK ? REASON.BAD_VALUE : reason };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyCriticalChGuard };
