'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  TOO_MANY: 'too-many',
  UNSAFE_URL: 'unsafe-url',
};

const HEADER = 'link';
const MAX_ENTRIES = 8;
const MAX_LENGTH = 1024;
const ENTRY = /^<([^<>\s]{1,512})>(.*)$/;

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

function safeUrl(url) {
  const lower = url.toLowerCase();
  if (lower.startsWith('https://') || lower.startsWith('/') || lower.startsWith('./')) return true;
  if (lower.startsWith('http://')) return false;
  return false;
}

function applyEarlyHintGuard(headers) {
  const raw = rawValue(headers, HEADER);
  if (raw === null) return { changed: false, reason: REASON.MISSING };
  const key = headerKey(headers, HEADER);
  const text = Array.isArray(raw) ? raw.map((v) => String(v)).join(',') : String(raw);
  if (/[\u0000-\u0008\u000a-\u001f\u007f]/.test(text)) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (text.length > MAX_LENGTH) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  const entries = [];
  for (const chunk of text.split(',')) {
    const trimmed = chunk.trim();
    if (trimmed !== '') entries.push(trimmed);
  }
  if (entries.length === 0) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (entries.length > MAX_ENTRIES) {
    headers[key] = entries.slice(0, MAX_ENTRIES).join(', ');
    return { changed: true, reason: REASON.TOO_MANY };
  }
  let reason = REASON.OK;
  const safe = [];
  for (const entry of entries) {
    const match = ENTRY.exec(entry);
    if (!match) {
      reason = REASON.BAD_VALUE;
      continue;
    }
    if (!safeUrl(match[1])) {
      reason = REASON.UNSAFE_URL;
      continue;
    }
    if (/rel=preload/i.test(match[2]) && !/;\s*as=/i.test(match[2])) {
      reason = REASON.BAD_VALUE;
      continue;
    }
    safe.push(entry);
  }
  if (safe.length === 0) {
    delete headers[key];
    return { changed: true, reason: reason === REASON.OK ? REASON.BAD_VALUE : reason };
  }
  if (reason !== REASON.OK) {
    headers[key] = safe.join(', ');
    return { changed: true, reason };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyEarlyHintGuard };
