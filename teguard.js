'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  UNSUPPORTED: 'unsupported-coding',
};

const HEADER = 'te';
const ALLOWED = new Set(['trailers', 'deflate', 'gzip', 'compress']);

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function firstValue(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return '';
  const raw = headers[key];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === 'string' ? value : '';
}

function applyTeGuard(headers) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING };
  const text = value.trim().toLowerCase();
  if (!text) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.MISSING };
  }
  const tokens = text.split(',').map((token) => token.trim()).filter(Boolean);
  const kept = [];
  let unsupported = false;
  for (const token of tokens) {
    const coding = token.split(';')[0].trim();
    if (!ALLOWED.has(coding)) {
      unsupported = true;
      continue;
    }
    kept.push(coding);
  }
  if (kept.length === 0) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: unsupported ? REASON.UNSUPPORTED : REASON.BAD_VALUE };
  }
  if (unsupported) {
    headers[headerKey(headers, HEADER)] = kept.join(', ');
    return { changed: true, reason: REASON.UNSUPPORTED };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyTeGuard };
