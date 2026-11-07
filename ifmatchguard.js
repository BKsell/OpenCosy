'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  TOO_MANY: 'too-many',
  WILDCARD_MIXED: 'wildcard-mixed',
};

const HEADER = 'if-match';
const ETAG = /^(W\/)?"[!#$%&'*+.^_`|~0-9A-Za-z:\-]{1,128}"$/;
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

function splitList(raw) {
  if (Array.isArray(raw)) return raw.map((v) => String(v)).join(',').split(',');
  if (typeof raw !== 'string') return [];
  return raw.split(',');
}

function applyIfMatchGuard(headers) {
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
  if (entries.length > 1 && entries.some((v) => v === '*')) {
    delete headers[key];
    return { changed: true, reason: REASON.WILDCARD_MIXED };
  }
  for (const entry of entries) {
    if (entry === '*') continue;
    if (!ETAG.test(entry)) {
      delete headers[key];
      return { changed: true, reason: REASON.BAD_VALUE };
    }
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyIfMatchGuard };
