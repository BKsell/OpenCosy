'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  TOO_MANY: 'too-many',
  TOO_LONG: 'too-long',
};

const HEADER = 'baggage';
const MAX_MEMBERS = 16;
const MAX_LENGTH = 4096;
const MEMBER = /^[A-Za-z0-9_.-]{1,64}=[\x20-\x7e]{0,256}(;[A-Za-z0-9_.-]{1,64}=[\x20-\x7e]{0,128}){0,3}$/;

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

function applyBaggageGuard(headers) {
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
  const members = text.split(',').map((v) => v.trim()).filter(Boolean);
  if (members.length === 0) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (members.length > MAX_MEMBERS) {
    headers[key] = members.slice(0, MAX_MEMBERS).join(', ');
    return { changed: true, reason: REASON.TOO_MANY };
  }
  const safe = [];
  let dropped = false;
  const seen = new Set();
  for (const member of members) {
    const eq = member.indexOf('=');
    const name = eq > 0 ? member.slice(0, eq) : '';
    if (!MEMBER.test(member) || seen.has(name)) {
      dropped = true;
      continue;
    }
    seen.add(name);
    safe.push(member);
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

module.exports = { REASON, applyBaggageGuard };
