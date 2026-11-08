'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  UNSAFE: 'unsafe-scheme',
  TOO_MANY: 'too-many',
};

const HEADER = 'x-forwarded-proto';
const SCHEMES = new Set(['http', 'https']);
const MAX_HOPS = 4;

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

function applyXForwardedProtoGuard(headers) {
  const raw = rawValue(headers, HEADER);
  if (raw === null) return { changed: false, reason: REASON.MISSING };
  const key = headerKey(headers, HEADER);
  const text = Array.isArray(raw) ? raw.map((v) => String(v)).join(',') : String(raw);
  if (/[\u0000-\u0008\u000a-\u001f\u007f]/.test(text)) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  const hops = text.split(',').map((v) => v.trim().toLowerCase()).filter(Boolean);
  if (hops.length === 0) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (hops.length > MAX_HOPS) {
    headers[key] = hops.slice(0, MAX_HOPS).join(', ');
    return { changed: true, reason: REASON.TOO_MANY };
  }
  for (const hop of hops) {
    if (!SCHEMES.has(hop)) {
      delete headers[key];
      return { changed: true, reason: REASON.UNSAFE };
    }
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyXForwardedProtoGuard };
