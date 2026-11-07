'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  ABSOLUTE_URL: 'absolute-url',
  TRAVERSAL: 'traversal',
  TOO_LONG: 'too-long',
  DUPLICATE: 'duplicate',
};

const HEADER = 'x-original-url';
const MAX_LENGTH = 2048;

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

function single(raw) {
  if (Array.isArray(raw)) {
    if (raw.length !== 1) return null;
    return String(raw[0]).trim();
  }
  if (typeof raw !== 'string') return null;
  return raw.trim();
}

function hasTraversal(path) {
  const segments = path.split('/');
  let depth = 0;
  for (const segment of segments) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') {
      depth -= 1;
      if (depth < 0) return true;
      continue;
    }
    depth += 1;
  }
  return false;
}

function applyXOriginalUrlGuard(headers) {
  const raw = rawValue(headers, HEADER);
  if (raw === null) return { changed: false, reason: REASON.MISSING };
  const key = headerKey(headers, HEADER);
  const value = single(raw);
  if (value === null) {
    delete headers[key];
    return { changed: true, reason: REASON.DUPLICATE };
  }
  if (value === '') {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (value.length > MAX_LENGTH) {
    delete headers[key];
    return { changed: true, reason: REASON.TOO_LONG };
  }
  if (/[\u0000-\u0008\u000a-\u001f\u007f]/.test(value)) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (!value.startsWith('/') || value.startsWith('//') || /^\/\s*$/.test(value)) {
    delete headers[key];
    return { changed: true, reason: REASON.ABSOLUTE_URL };
  }
  const pathOnly = value.split('?')[0].split('#')[0];
  if (pathOnly.includes('\\') || hasTraversal(pathOnly)) {
    delete headers[key];
    return { changed: true, reason: REASON.TRAVERSAL };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyXOriginalUrlGuard };
