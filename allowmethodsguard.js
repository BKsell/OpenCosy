'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  WILDCARD: 'wildcard',
  DUPLICATE: 'duplicate',
};

const HEADER = 'access-control-allow-methods';
const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'TRACE']);
const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const DEFAULT = 'GET, HEAD, POST, OPTIONS';

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

function list(raw) {
  if (Array.isArray(raw)) return raw.map((v) => String(v)).join(',').split(',');
  if (typeof raw !== 'string') return [];
  return raw.split(',');
}

function applyAllowMethodsGuard(headers, options) {
  const raw = rawValue(headers, HEADER);
  if (raw === null) return { changed: false, reason: REASON.MISSING };
  const key = headerKey(headers, HEADER);
  const entries = list(raw).map((v) => v.trim()).filter(Boolean);
  if (entries.length === 0) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  const credentials = options && options.credentials === true;
  let reason = REASON.OK;
  const seen = new Set();
  const safe = [];
  for (const entry of entries) {
    const upper = entry.toUpperCase();
    if (entry === '*' || upper === '*') {
      reason = REASON.WILDCARD;
      continue;
    }
    if (!TOKEN.test(entry) || (credentials && upper === 'TRACE')) {
      reason = REASON.BAD_VALUE;
      continue;
    }
    if (seen.has(upper)) {
      reason = REASON.DUPLICATE;
      continue;
    }
    seen.add(upper);
    safe.push(METHODS.has(upper) ? upper : entry);
  }
  if (safe.length === 0) {
    headers[key] = DEFAULT;
    return { changed: true, reason: reason === REASON.OK ? REASON.BAD_VALUE : reason };
  }
  const joined = safe.join(', ');
  if (reason !== REASON.OK || joined !== entries.join(', ')) {
    headers[key] = joined;
    return { changed: true, reason };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyAllowMethodsGuard };
