'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  OVERLONG: 'overlong',
  INJECTION: 'log-injection',
};

const HEADER = 'x-request-id';
const MAX_LENGTH = 128;
const SAFE_RE = /^[A-Za-z0-9._:-]{8,128}$/;

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

function hasInjection(text) {
  if (/[\u0000-\u001f\u007f]/.test(text)) return true;
  if (text.includes('\\n') || text.includes('\\r')) return true;
  if (text.includes('\u2028') || text.includes('\u2029')) return true;
  return false;
}

function applyXRequestIdGuard(headers) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING };
  const text = value.trim();
  if (!text) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.MISSING };
  }
  if (text.length > MAX_LENGTH) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.OVERLONG };
  }
  if (hasInjection(text)) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.INJECTION };
  }
  if (!SAFE_RE.test(text)) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (text !== value) {
    headers[headerKey(headers, HEADER)] = text;
    return { changed: true, reason: REASON.OK };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyXRequestIdGuard };
