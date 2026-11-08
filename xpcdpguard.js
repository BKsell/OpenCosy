'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
};

const HEADER = 'x-permitted-cross-domain-policies';
const ALLOWED = new Set(['none', 'master-only', 'by-content-type', 'all']);

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function applyXpcdpGuard(headers) {
  const key = headerKey(headers, HEADER);
  if (!key) return { changed: false, reason: REASON.MISSING };
  const raw = headers[key];
  const value = Array.isArray(raw) ? raw.join(',') : raw;
  const normalized = typeof value === 'string' ? value.trim().toLowerCase() : '';
  if (!normalized) {
    headers[key] = 'none';
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (normalized.includes(',')) {
    headers[key] = 'none';
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (!ALLOWED.has(normalized)) {
    headers[key] = 'none';
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (key !== HEADER) {
    headers[HEADER] = headers[key];
    delete headers[key];
    return { changed: true, reason: REASON.OK };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyXpcdpGuard };
