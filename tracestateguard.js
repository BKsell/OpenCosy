'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  TOO_MANY: 'too-many',
  TOO_LONG: 'too-long',
};

const HEADER = 'tracestate';
const MAX_ENTRIES = 32;
const MAX_LENGTH = 512;
const MEMBER = /^[a-z][a-z0-9_\-*/]{0,255}=[\x20-\x7e]{1,256}$/;

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

function applyTraceStateGuard(headers) {
  const raw = rawValue(headers, HEADER);
  if (raw === null) return { changed: false, reason: REASON.MISSING };
  const key = headerKey(headers, HEADER);
  const text = Array.isArray(raw) ? raw.map((v) => String(v)).join(',') : String(raw);
  if (text.length > MAX_LENGTH) {
    delete headers[key];
    return { changed: true, reason: REASON.TOO_LONG };
  }
  if (/[\u0000-\u0008\u000a-\u001f\u007f]/.test(text)) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  const entries = text.split(',').map((v) => v.trim()).filter(Boolean);
  if (entries.length === 0) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (entries.length > MAX_ENTRIES) {
    headers[key] = entries.slice(0, MAX_ENTRIES).join(', ');
    return { changed: true, reason: REASON.TOO_MANY };
  }
  const safe = [];
  let dropped = false;
  const seen = new Set();
  for (const entry of entries) {
    const eq = entry.indexOf('=');
    const name = eq > 0 ? entry.slice(0, eq) : '';
    if (!MEMBER.test(entry) || seen.has(name)) {
      dropped = true;
      continue;
    }
    seen.add(name);
    safe.push(entry);
  }
  if (safe.length === 0) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (dropped) {
    headers[key] = safe.join(', ');
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyTraceStateGuard };
