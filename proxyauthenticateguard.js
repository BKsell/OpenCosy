'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  WEAK_SCHEME: 'weak-scheme',
  TOO_MANY: 'too-many',
};

const HEADER = 'proxy-authenticate';
const STRONG = new Set(['digest', 'negotiate', 'ntlm', 'bearer']);
const WEAK = new Set(['basic']);
const TOKEN = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,32}$/;
const MAX_CHALLENGES = 3;

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

function applyProxyAuthenticateGuard(headers) {
  const raw = rawValue(headers, HEADER);
  if (raw === null) return { changed: false, reason: REASON.MISSING };
  const key = headerKey(headers, HEADER);
  const text = Array.isArray(raw) ? raw.map((v) => String(v)).join(',') : String(raw);
  if (/[\u0000-\u0008\u000a-\u001f\u007f]/.test(text)) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  const schemeMatch = /^([A-Za-z0-9!#$%&'*+.^_`|~-]{1,32})(?:\s+(.*))?$/.exec(text.trim());
  if (!schemeMatch) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  const scheme = schemeMatch[1];
  const params = (schemeMatch[2] || '').trim();
  if (!TOKEN.test(scheme)) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (WEAK.has(scheme.toLowerCase())) {
    delete headers[key];
    return { changed: true, reason: REASON.WEAK_SCHEME };
  }
  if (!STRONG.has(scheme.toLowerCase())) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (params === '') {
    return { changed: false, reason: REASON.OK };
  }
  const pairs = params.split(',').map((v) => v.trim()).filter(Boolean);
  if (pairs.length > MAX_CHALLENGES + 4) {
    headers[key] = `${scheme} ${pairs.slice(0, MAX_CHALLENGES + 4).join(', ')}`;
    return { changed: true, reason: REASON.TOO_MANY };
  }
  for (const pair of pairs) {
    const eq = pair.indexOf('=');
    if (eq <= 0) {
      delete headers[key];
      return { changed: true, reason: REASON.BAD_VALUE };
    }
    const name = pair.slice(0, eq).trim();
    if (!TOKEN.test(name)) {
      delete headers[key];
      return { changed: true, reason: REASON.BAD_VALUE };
    }
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyProxyAuthenticateGuard };
