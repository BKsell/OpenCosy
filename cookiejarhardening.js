'use strict';

const REASON = {
  ok: 'ok',
  publicSuffix: 'public-suffix-domain',
  ipDomain: 'ip-domain',
  hostPrefix: 'host-prefix-insecure',
  securePrefix: 'secure-prefix-insecure',
  samesiteNone: 'samesite-none-insecure',
  oversized: 'oversized-cookie',
  tooMany: 'too-many-cookies',
  malformed: 'malformed-cookie',
  controlChars: 'control-chars',
};

const PUBLIC_SUFFIXES = new Set([
  'com', 'net', 'org', 'io', 'co', 'cn', 'ru', 'jp', 'de', 'fr', 'us', 'uk',
  'com.cn', 'co.uk', 'org.uk', 'gov.cn', 'edu.cn', 'com.hk', 'com.tw',
]);

const MAX_COOKIE_BYTES = 4096;
const MAX_COOKIES = 50;

function lowerHeaderName(name) {
  return String(name || '').toLowerCase();
}

function headerValues(headers, name) {
  const target = lowerHeaderName(name);
  for (const key of Object.keys(headers || {})) {
    if (lowerHeaderName(key) !== target) continue;
    const value = headers[key];
    if (Array.isArray(value)) return value.slice();
    if (typeof value === 'string') return [value];
  }
  return [];
}

function deleteHeader(headers, name) {
  const target = lowerHeaderName(name);
  for (const key of Object.keys(headers || {})) {
    if (lowerHeaderName(key) === target) delete headers[key];
  }
}

function setHeader(headers, name, values) {
  deleteHeader(headers, name);
  if (values.length) headers[name] = values;
}

function parseCookie(raw) {
  const text = String(raw || '');
  const parts = text.split(';');
  const pair = parts.shift() || '';
  const eq = pair.indexOf('=');
  if (eq <= 0) return null;
  const name = pair.slice(0, eq).trim();
  const value = pair.slice(eq + 1).trim();
  if (!name) return null;
  const attrs = { domain: null, path: null, secure: false, httpOnly: false, sameSite: null };
  for (const part of parts) {
    const idx = part.indexOf('=');
    const key = (idx < 0 ? part : part.slice(0, idx)).trim().toLowerCase();
    const val = idx < 0 ? '' : part.slice(idx + 1).trim();
    if (key === 'domain') attrs.domain = val.toLowerCase();
    else if (key === 'path') attrs.path = val;
    else if (key === 'secure') attrs.secure = true;
    else if (key === 'httponly') attrs.httpOnly = true;
    else if (key === 'samesite') attrs.sameSite = val.toLowerCase();
  }
  return { name, value, attrs, raw: text };
}

function isIpDomain(domain) {
  if (!domain) return false;
  const bare = domain.replace(/^\./, '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(bare)) return true;
  return /^\[?[0-9a-f:]{6,}\]?$/i.test(bare) && bare.includes(':');
}

function isPublicSuffix(domain) {
  if (!domain) return false;
  const bare = domain.replace(/^\./, '');
  return PUBLIC_SUFFIXES.has(bare);
}

function hasControlChars(text) {
  return /[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/.test(String(text || ''));
}

function inspectCookie(raw) {
  const cookie = parseCookie(raw);
  if (!cookie) return { reason: REASON.malformed, drop: true, cookie: null };
  if (hasControlChars(cookie.name) || hasControlChars(cookie.value)) {
    return { reason: REASON.controlChars, drop: true, cookie };
  }
  if (Buffer.byteLength(cookie.name + cookie.value, 'utf8') > MAX_COOKIE_BYTES) {
    return { reason: REASON.oversized, drop: true, cookie };
  }
  if (isIpDomain(cookie.attrs.domain)) {
    return { reason: REASON.ipDomain, drop: true, cookie };
  }
  if (isPublicSuffix(cookie.attrs.domain)) {
    return { reason: REASON.publicSuffix, drop: true, cookie };
  }
  if (cookie.name.startsWith('__Host-')) {
    if (!cookie.attrs.secure || cookie.attrs.domain || cookie.attrs.path !== '/') {
      return { reason: REASON.hostPrefix, drop: true, cookie };
    }
  }
  if (cookie.name.startsWith('__Secure-') && !cookie.attrs.secure) {
    return { reason: REASON.securePrefix, drop: true, cookie };
  }
  if (cookie.attrs.sameSite === 'none' && !cookie.attrs.secure) {
    return { reason: REASON.samesiteNone, drop: true, cookie };
  }
  return { reason: REASON.ok, drop: false, cookie };
}

function evaluateCookieJar(headers) {
  const values = headerValues(headers, 'set-cookie');
  const dropped = [];
  const kept = [];
  let reason = REASON.ok;
  for (const raw of values) {
    const verdict = inspectCookie(raw);
    if (verdict.drop) {
      dropped.push({ raw, reason: verdict.reason });
      if (reason === REASON.ok) reason = verdict.reason;
      continue;
    }
    kept.push(raw);
  }
  if (kept.length > MAX_COOKIES) {
    const overflow = kept.length - MAX_COOKIES;
    for (let i = 0; i < overflow; i += 1) {
      dropped.push({ raw: kept[kept.length - 1 - i], reason: REASON.tooMany });
    }
    kept.length = MAX_COOKIES;
    reason = reason === REASON.ok ? REASON.tooMany : reason;
  }
  return { reason, kept, dropped, changed: dropped.length > 0 };
}

function applyCookieJarHardening(headers) {
  const verdict = evaluateCookieJar(headers);
  if (verdict.changed) setHeader(headers, 'Set-Cookie', verdict.kept);
  return verdict;
}

function describeReason(reason) {
  switch (reason) {
    case REASON.ok: return 'cookie scope acceptable';
    case REASON.publicSuffix: return 'cookie scoped to a public suffix';
    case REASON.ipDomain: return 'cookie scoped to an IP literal';
    case REASON.hostPrefix: return '__Host- cookie missing Secure/Path or carrying Domain';
    case REASON.securePrefix: return '__Secure- cookie missing Secure';
    case REASON.samesiteNone: return 'SameSite=None cookie without Secure';
    case REASON.oversized: return 'cookie exceeds the 4KB limit';
    case REASON.tooMany: return 'response sets too many cookies';
    case REASON.malformed: return 'cookie pair cannot be parsed';
    case REASON.controlChars: return 'cookie carries control or bidi characters';
    default: return 'unknown cookie verdict';
  }
}

module.exports = {
  REASON,
  MAX_COOKIE_BYTES,
  MAX_COOKIES,
  parseCookie,
  inspectCookie,
  evaluateCookieJar,
  applyCookieJarHardening,
  describeReason,
};
