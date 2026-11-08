'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  DUPLICATE: 'duplicate',
  UNSAFE_PARAM: 'unsafe-parameter',
};

const HEADER = 'content-type';
const MEDIA = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+\/[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$/;
const SAFE_PARAMS = new Set(['charset', 'boundary', 'type', 'start']);
const MAX_LENGTH = 200;

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

function applyContentTypeGuard(headers) {
  const raw = rawValue(headers, HEADER);
  if (raw === null) return { changed: false, reason: REASON.MISSING };
  const key = headerKey(headers, HEADER);
  const value = single(raw);
  if (value === null) {
    delete headers[key];
    return { changed: true, reason: REASON.DUPLICATE };
  }
  if (value === '') return { changed: false, reason: REASON.OK };
  if (value.length > MAX_LENGTH) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  const parts = value.split(';');
  const media = parts[0].trim().toLowerCase();
  if (!MEDIA.test(media)) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  for (const part of parts.slice(1)) {
    const trimmed = part.trim();
    if (trimmed === '') continue;
    const eq = trimmed.indexOf('=');
    if (eq <= 0) {
      delete headers[key];
      return { changed: true, reason: REASON.UNSAFE_PARAM };
    }
    const name = trimmed.slice(0, eq).trim().toLowerCase();
    if (!SAFE_PARAMS.has(name)) {
      delete headers[key];
      return { changed: true, reason: REASON.UNSAFE_PARAM };
    }
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyContentTypeGuard };
