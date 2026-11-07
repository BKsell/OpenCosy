'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  OVERLONG: 'overlong',
  TOO_MANY: 'too-many',
  BAD_TOKEN: 'bad-token',
  BAD_WEIGHT: 'bad-weight',
  IDENTITY_CONFLICT: 'identity-conflict',
};

const HEADER = 'accept-encoding';
const MAX_LENGTH = 256;
const MAX_CODINGS = 6;
const ALLOWED = new Set(['gzip', 'deflate', 'br', 'zstd', 'identity', '*']);
const TOKEN_RE = /^[a-z0-9*_-]{1,24}$/;

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

function parseCoding(token) {
  const text = token.trim().toLowerCase();
  if (!text) return null;
  const semi = text.indexOf(';');
  const coding = (semi >= 0 ? text.slice(0, semi) : text).trim();
  if (!TOKEN_RE.test(coding)) return { ok: false, reason: REASON.BAD_TOKEN };
  if (!ALLOWED.has(coding)) return { ok: false, reason: REASON.BAD_TOKEN };
  if (semi < 0) return { ok: true, coding, weight: 1 };
  const params = text.slice(semi + 1).trim();
  const match = /^q=(\d(?:\.\d{0,3})?)$/.exec(params);
  if (!match) return { ok: false, reason: REASON.BAD_WEIGHT };
  const weight = Number(match[1]);
  if (!Number.isFinite(weight) || weight < 0 || weight > 1) {
    return { ok: false, reason: REASON.BAD_WEIGHT };
  }
  return { ok: true, coding, weight };
}

function applyAcceptEncodingGuard(headers) {
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
  const tokens = text.split(',');
  if (tokens.length > MAX_CODINGS) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.TOO_MANY };
  }
  const kept = [];
  let badToken = false;
  let badWeight = false;
  let identityConflict = false;
  for (const token of tokens) {
    const parsed = parseCoding(token);
    if (!parsed) continue;
    if (!parsed.ok) {
      if (parsed.reason === REASON.BAD_WEIGHT) badWeight = true;
      else badToken = true;
      continue;
    }
    if (parsed.coding === 'identity' && parsed.weight === 0) {
      identityConflict = true;
      continue;
    }
    const entry = parsed.weight === 1 ? parsed.coding : parsed.coding + ';q=' + parsed.weight;
    if (!kept.includes(entry)) kept.push(entry);
  }
  const reason = badWeight ? REASON.BAD_WEIGHT : badToken ? REASON.BAD_TOKEN : identityConflict ? REASON.IDENTITY_CONFLICT : REASON.OK;
  if (kept.length === 0) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason };
  }
  if (reason !== REASON.OK || kept.length !== tokens.length) {
    headers[headerKey(headers, HEADER)] = kept.join(', ');
    return { changed: true, reason: reason === REASON.OK ? REASON.BAD_TOKEN : reason };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyAcceptEncodingGuard };
