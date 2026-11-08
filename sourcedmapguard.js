'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  EXTERNAL: 'external-source',
  BAD_PATH: 'bad-path',
  OVERLONG: 'overlong',
  DATA_URI: 'data-uri',
};

const HEADERS = ['sourcemap', 'x-sourcemap'];
const MAX_LENGTH = 512;

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

function inspectPath(value) {
  const text = value.trim();
  if (!text) return { reason: REASON.BAD_PATH, ok: false };
  if (/^data:/i.test(text)) return { reason: REASON.DATA_URI, ok: false };
  if (/^[a-z][a-z0-9+.-]*:/i.test(text) || text.startsWith('//')) {
    return { reason: REASON.EXTERNAL, ok: false };
  }
  if (text.includes('\\') || text.includes('..') || /[\u0000-\u001f\u007f]/.test(text)) {
    return { reason: REASON.BAD_PATH, ok: false };
  }
  if (!text.startsWith('/')) {
    return { reason: REASON.BAD_PATH, ok: false };
  }
  return { reason: REASON.OK, ok: true };
}

function applySourceMapGuard(headers) {
  let changed = false;
  let reason = REASON.MISSING;
  for (const name of HEADERS) {
    const key = headerKey(headers, name);
    if (!key) continue;
    const raw = headers[key];
    const value = Array.isArray(raw) ? raw[0] : raw;
    if (typeof value !== 'string' || !value.trim()) {
      delete headers[key];
      changed = true;
      reason = REASON.MISSING;
      continue;
    }
    if (value.length > MAX_LENGTH) {
      delete headers[key];
      changed = true;
      reason = REASON.OVERLONG;
      continue;
    }
    const inspected = inspectPath(value);
    if (!inspected.ok) {
      delete headers[key];
      changed = true;
      reason = inspected.reason;
      continue;
    }
    if (reason === REASON.MISSING) reason = REASON.OK;
  }
  return { changed, reason };
}

module.exports = { REASON, applySourceMapGuard };
