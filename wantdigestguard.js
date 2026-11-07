'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  WEAK_ALGORITHM: 'weak-algorithm',
  TOO_MANY: 'too-many',
};

const HEADER = 'want-digest';
const STRONG = new Set(['sha-256', 'sha-512', 'sha-256-sess', 'sha-512-sess']);
const WEAK = new Set(['md5', 'sha', 'sha-1', 'md5-sess', 'crc32']);
const MAX_ENTRIES = 3;

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

function applyWantDigestGuard(headers) {
  const raw = rawValue(headers, HEADER);
  if (raw === null) return { changed: false, reason: REASON.MISSING };
  const key = headerKey(headers, HEADER);
  const text = Array.isArray(raw) ? raw.map((v) => String(v)).join(',') : String(raw);
  const entries = text.split(',').map((v) => v.split(';')[0].trim().toLowerCase()).filter(Boolean);
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
    if (!STRONG.has(entry)) {
      reason = WEAK.has(entry) ? REASON.WEAK_ALGORITHM : REASON.BAD_VALUE;
      continue;
    }
    if (seen.has(entry)) continue;
    seen.add(entry);
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

module.exports = { REASON, applyWantDigestGuard };
