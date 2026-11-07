'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  TOO_MANY: 'too-many',
  WILDCARD: 'wildcard',
};

const HEADER = 'access-control-allow-headers';
const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const MAX_ENTRIES = 24;

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

function applyAllowHeadersGuard(headers) {
  const raw = rawValue(headers, HEADER);
  if (raw === null) return { changed: false, reason: REASON.MISSING };
  const key = headerKey(headers, HEADER);
  const text = Array.isArray(raw) ? raw.map((v) => String(v)).join(',') : String(raw);
  if (/[\u0000-\u0008\u000a-\u001f\u007f]/.test(text)) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  const entries = text.split(',').map((v) => v.trim()).filter(Boolean);
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
    if (entry === '*') {
      reason = REASON.WILDCARD;
      continue;
    }
    if (!TOKEN.test(entry)) {
      reason = REASON.BAD_VALUE;
      continue;
    }
    const lower = entry.toLowerCase();
    if (seen.has(lower)) continue;
    seen.add(lower);
    safe.push(lower);
  }
  if (safe.length === 0) {
    delete headers[key];
    return { changed: true, reason: reason === REASON.OK ? REASON.BAD_VALUE : reason };
  }
  const joined = safe.join(', ');
  if (reason !== REASON.OK || joined !== entries.join(', ')) {
    headers[key] = joined;
    return { changed: true, reason: reason === REASON.OK ? REASON.DUPLICATE : reason };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyAllowHeadersGuard };
