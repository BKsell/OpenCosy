'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  OVERLONG: 'overlong',
  BAD_TAG: 'bad-tag',
  BAD_WEIGHT: 'bad-weight',
  TOO_MANY: 'too-many',
};

const HEADER = 'accept-language';
const MAX_LENGTH = 256;
const MAX_ENTRIES = 10;
const TAG_RE = /^[a-z]{1,8}(-[a-z0-9]{1,8}){0,3}$/;

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

function parseEntry(token) {
  const text = token.trim();
  if (!text) return null;
  const semi = text.indexOf(';');
  const tag = (semi >= 0 ? text.slice(0, semi) : text).trim().toLowerCase();
  const params = semi >= 0 ? text.slice(semi + 1).trim() : '';
  if (tag === '*') return { tag, weight: 1, ok: true, wildcard: true };
  if (!TAG_RE.test(tag)) return { tag, ok: false };
  let weight = 1;
  let badWeight = false;
  if (params) {
    const match = /^q=(\d(?:\.\d{0,3})?)$/i.exec(params);
    if (!match) return { tag, ok: false, badWeight: true };
    weight = Number(match[1]);
    if (!Number.isFinite(weight) || weight < 0 || weight > 1) badWeight = true;
  }
  return { tag, weight, ok: !badWeight, badWeight };
}

function applyAcceptLanguageGuard(headers) {
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
  if (tokens.length > MAX_ENTRIES) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.TOO_MANY };
  }
  const kept = [];
  let badTag = false;
  let badWeight = false;
  for (const token of tokens) {
    const entry = parseEntry(token);
    if (!entry) continue;
    if (!entry.ok) {
      if (entry.badWeight) badWeight = true;
      else badTag = true;
      continue;
    }
    kept.push(entry.weight === 1 ? entry.tag : entry.tag + ';q=' + entry.weight);
  }
  if (kept.length === 0) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: badWeight ? REASON.BAD_WEIGHT : REASON.BAD_TAG };
  }
  if (badTag || badWeight) {
    headers[headerKey(headers, HEADER)] = kept.join(', ');
    return { changed: true, reason: badWeight ? REASON.BAD_WEIGHT : REASON.BAD_TAG };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyAcceptLanguageGuard, parseEntry };
