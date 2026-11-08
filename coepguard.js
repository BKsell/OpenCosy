'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  DUPLICATE: 'duplicate',
};

const HEADER = 'cross-origin-embedder-policy';
const ALLOWED = new Set(['require-corp', 'credentialless', 'unsafe-none']);

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

function normalize(raw) {
  if (Array.isArray(raw)) {
    if (raw.length > 1) return { values: raw.map((v) => String(v)).map((v) => v.trim().toLowerCase()), duplicate: true };
    return { values: [String(raw[0] || '').trim().toLowerCase()], duplicate: false };
  }
  if (typeof raw !== 'string') return { values: [], duplicate: false };
  return { values: raw.split(',').map((v) => v.trim().toLowerCase()).filter(Boolean), duplicate: false };
}

function applyCoepGuard(headers) {
  const raw = rawValue(headers, HEADER);
  if (raw === null) return { changed: false, reason: REASON.MISSING };
  const parsed = normalize(raw);
  if (parsed.values.length === 0) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (parsed.duplicate || parsed.values.length > 1) {
    headers[headerKey(headers, HEADER)] = 'require-corp';
    return { changed: true, reason: REASON.DUPLICATE };
  }
  const value = parsed.values[0];
  if (!ALLOWED.has(value)) {
    headers[headerKey(headers, HEADER)] = 'require-corp';
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyCoepGuard };
