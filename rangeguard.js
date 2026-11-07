'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_UNIT: 'bad-unit',
  BAD_RANGE: 'bad-range',
  TOO_MANY: 'too-many',
  OVERLONG: 'overlong',
};

const HEADER = 'range';
const MAX_LENGTH = 256;
const MAX_RANGES = 3;
const RANGE_RE = /^\d{0,18}-\d{0,18}$/;

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

function validRange(token) {
  const text = token.trim();
  if (!RANGE_RE.test(text)) return false;
  const dash = text.indexOf('-');
  const start = text.slice(0, dash);
  const end = text.slice(dash + 1);
  if (start === '' && end === '') return false;
  if (start === '') return Number(end) > 0;
  if (end === '') return true;
  return Number(end) >= Number(start);
}

function applyRangeGuard(headers) {
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
  const eq = text.indexOf('=');
  const unit = (eq >= 0 ? text.slice(0, eq) : text).trim().toLowerCase();
  if (eq < 0 || unit !== 'bytes') {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.BAD_UNIT };
  }
  const spec = text.slice(eq + 1);
  const tokens = spec.split(',');
  if (tokens.length > MAX_RANGES) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.TOO_MANY };
  }
  const kept = [];
  let dropped = false;
  for (const token of tokens) {
    const part = token.trim();
    if (!part) continue;
    if (!validRange(part)) {
      dropped = true;
      continue;
    }
    kept.push(part);
  }
  if (kept.length === 0) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.BAD_RANGE };
  }
  if (dropped) {
    headers[headerKey(headers, HEADER)] = 'bytes=' + kept.join(',');
    return { changed: true, reason: REASON.BAD_RANGE };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyRangeGuard, validRange };
