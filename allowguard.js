'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  WILDCARD: 'wildcard',
  TRACE: 'trace-forbidden',
  TOO_MANY: 'too-many',
};

const HEADER = 'allow';
const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const MAX_ENTRIES = 16;

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

function applyAllowGuard(headers) {
  const raw = rawValue(headers, HEADER);
  if (raw === null) return { changed: false, reason: REASON.MISSING };
  const key = headerKey(headers, HEADER);
  const text = Array.isArray(raw) ? raw.map((v) => String(v)).join(',') : String(raw);
  const entries = text.split(',').map((v) => v.trim()).filter(Boolean);
  if (entries.length === 0) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  let reason = REASON.OK;
  const safe = [];
  const seen = new Set();
  for (const entry of entries) {
    const upper = entry.toUpperCase();
    if (entry === '*' || upper === '*') {
      reason = REASON.WILDCARD;
      continue;
    }
    if (!TOKEN.test(entry)) {
      reason = REASON.BAD_VALUE;
      continue;
    }
    if (upper === 'TRACE') {
      reason = REASON.TRACE;
      continue;
    }
    if (seen.has(upper)) continue;
    seen.add(upper);
    safe.push(upper);
  }
  if (safe.length === 0) {
    delete headers[key];
    return { changed: true, reason: reason === REASON.OK ? REASON.BAD_VALUE : reason };
  }
  if (safe.length > MAX_ENTRIES) {
    headers[key] = safe.slice(0, MAX_ENTRIES).join(', ');
    return { changed: true, reason: REASON.TOO_MANY };
  }
  const joined = safe.join(', ');
  if (reason !== REASON.OK || joined !== entries.join(', ')) {
    headers[key] = joined;
    return { changed: true, reason };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyAllowGuard };
