'use strict';
const { describeReasonTable } = require('./reasontext');

const { headerKey } = require('./headerutil_core');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed-cookie',
  BAD_NAME: 'invalid-cookie-name',
  HOST_PREFIX_VIOLATION: 'host-prefix-violation',
  SECURE_PREFIX_VIOLATION: 'secure-prefix-violation',
  NONE_WITHOUT_SECURE: 'samesite-none-without-secure',
  BAD_SAMESITE: 'invalid-samesite',
  SAMESITE_MISSING: 'samesite-missing',
  NOT_HTTPONLY: 'httponly-missing',
  DUP_ATTRIBUTE: 'duplicate-attribute',
  OVERLONG: 'cookie-overlong',
};

const SAME_SITE_VALUES = new Set(['strict', 'lax', 'none']);
const KNOWN_ATTRIBUTES = new Set([
  'path',
  'domain',
  'expires',
  'max-age',
  'secure',
  'httponly',
  'samesite',
  'partitioned',
  'priority',
]);

const MAX_COOKIE_LENGTH = 4096;
const PROTECTED_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

function splitCookie(text) {
  const parts = text.split(';');
  const pair = parts.shift() || '';
  const eq = pair.indexOf('=');
  if (eq <= 0) return null;
  const name = pair.slice(0, eq).trim();
  const value = pair.slice(eq + 1).trim();
  if (!PROTECTED_NAME.test(name)) return null;
  const attributes = [];
  for (const raw of parts) {
    const item = raw.trim();
    if (!item) continue;
    const idx = item.indexOf('=');
    const key = (idx >= 0 ? item.slice(0, idx) : item).trim().toLowerCase();
    const attrValue = idx >= 0 ? item.slice(idx + 1).trim() : '';
    attributes.push({ key, value: attrValue });
  }
  return { name, value, attributes };
}

function attributeMap(attributes) {
  const map = new Map();
  let duplicates = false;
  for (const attr of attributes) {
    if (map.has(attr.key)) duplicates = true;
    map.set(attr.key, attr.value);
  }
  return { map, duplicates };
}

function hasAttribute(map, name) {
  return map.has(name);
}

function sanitizeCookie(text) {
  if (typeof text !== 'string') return { reason: REASON.MALFORMED, cookie: null };
  const trimmed = text.trim();
  if (!trimmed) return { reason: REASON.MALFORMED, cookie: null };
  if (trimmed.length > MAX_COOKIE_LENGTH) return { reason: REASON.OVERLONG, cookie: null };
  const parsed = splitCookie(trimmed);
  if (!parsed) return { reason: REASON.MALFORMED, cookie: null };
  const { map, duplicates } = attributeMap(parsed.attributes);
  const name = parsed.name;
  const lowerName = name.toLowerCase();
  const reasons = [];
  let rewrite = false;

  if (duplicates) reasons.push(REASON.DUP_ATTRIBUTE);
  const unknown = parsed.attributes.filter((attr) => !KNOWN_ATTRIBUTES.has(attr.key));
  if (unknown.length) reasons.push(REASON.BAD_NAME);

  if (lowerName.startsWith('__host-')) {
    if (hasAttribute(map, 'domain')) {
      reasons.push(REASON.HOST_PREFIX_VIOLATION);
      map.delete('domain');
      rewrite = true;
    }
    if (!hasAttribute(map, 'secure')) {
      reasons.push(REASON.HOST_PREFIX_VIOLATION);
      map.set('secure', '');
      rewrite = true;
    }
    if ((map.get('path') || '') !== '/') {
      reasons.push(REASON.HOST_PREFIX_VIOLATION);
      map.set('path', '/');
      rewrite = true;
    }
  } else if (lowerName.startsWith('__secure-')) {
    if (!hasAttribute(map, 'secure')) {
      reasons.push(REASON.SECURE_PREFIX_VIOLATION);
      map.set('secure', '');
      rewrite = true;
    }
  }

  const sameSite = (map.get('samesite') || '').toLowerCase();
  if (!sameSite) {
    reasons.push(REASON.SAMESITE_MISSING);
    map.set('samesite', 'Lax');
    rewrite = true;
  } else if (!SAME_SITE_VALUES.has(sameSite)) {
    reasons.push(REASON.BAD_SAMESITE);
    map.set('samesite', 'Lax');
    rewrite = true;
  } else if (sameSite === 'none' && !hasAttribute(map, 'secure')) {
    reasons.push(REASON.NONE_WITHOUT_SECURE);
    map.set('samesite', 'Lax');
    rewrite = true;
  }

  if (!hasAttribute(map, 'httponly')) {
    reasons.push(REASON.NOT_HTTPONLY);
  }

  if (!rewrite) {
    return { reason: reasons.length ? reasons[0] : REASON.OK, cookie: trimmed, reasons };
  }
  const rebuilt = [`${name}=${parsed.value}`];
  for (const [key, value] of map) {
    if (key === 'samesite') {
      rebuilt.push(`SameSite=${value}`);
      continue;
    }
    if (key === 'secure' || key === 'httponly' || key === 'partitioned') {
      rebuilt.push(key.charAt(0).toUpperCase() + key.slice(1));
      continue;
    }
    if (key === 'priority') {
      rebuilt.push(`Priority=${value}`);
      continue;
    }
    rebuilt.push(`${key.charAt(0).toUpperCase()}${key.slice(1)}=${value}`);
  }
  return { reason: reasons.length ? reasons[0] : REASON.OK, cookie: rebuilt.join('; '), reasons };
}

function inspectSetCookie(headers) {
  const key = headerKey(headers, 'set-cookie');
  if (!key) return { present: false, key: '', cookies: [], rewritten: [] };
  const raw = headers[key];
  const list = Array.isArray(raw) ? raw : [raw];
  const cookies = [];
  const rewritten = [];
  const findings = [];
  for (const item of list) {
    const result = sanitizeCookie(item);
    cookies.push(result);
    if (result.cookie && result.cookie !== item) rewritten.push(result.cookie);
    else if (result.cookie) rewritten.push(item);
    if (result.reason !== REASON.OK) {
      findings.push({ reason: result.reason, reasons: result.reasons || [result.reason] });
    }
  }
  return { present: true, key, cookies, rewritten, findings };
}

function applySetCookiePrefixGuard(headers) {
  const key = headerKey(headers, 'set-cookie');
  if (!key) return { changed: false, reason: REASON.MISSING, findings: [] };
  const result = inspectSetCookie(headers);
  const dropped = result.rewritten.filter((item) => typeof item === 'string' && item.length > 0);
  if (!dropped.length) {
    delete headers[key];
    return { changed: true, reason: REASON.MALFORMED, findings: result.findings };
  }
  const before = JSON.stringify(headers[key]);
  headers[key] = dropped.length === 1 ? dropped[0] : dropped;
  const after = JSON.stringify(headers[key]);
  const changed = before !== after;
  return {
    changed,
    reason: result.findings.length ? result.findings[0].reason : REASON.OK,
    findings: result.findings,
  };
}

const describeReason = describeReasonTable({
    [REASON.MISSING]: '未下发 Set-Cookie',
    [REASON.MALFORMED]: 'Set-Cookie 无法解析，已丢弃',
    [REASON.BAD_NAME]: 'Cookie 名称或属性非法',
    [REASON.HOST_PREFIX_VIOLATION]: '__Host- 前缀约束被违反，已修正',
    [REASON.SECURE_PREFIX_VIOLATION]: '__Secure- 前缀缺少 Secure，已补齐',
    [REASON.NONE_WITHOUT_SECURE]: 'SameSite=None 缺少 Secure，已改为 Lax',
    [REASON.BAD_SAMESITE]: 'SameSite 取值非法，已改为 Lax',
    [REASON.SAMESITE_MISSING]: '缺少 SameSite，已补 Lax',
    [REASON.NOT_HTTPONLY]: 'Cookie 未设置 HttpOnly',
    [REASON.DUP_ATTRIBUTE]: 'Cookie 属性重复',
    [REASON.OVERLONG]: 'Set-Cookie 超长，已丢弃',
  }, 'Set-Cookie 通过校验');

module.exports = {
  REASON,
  SAME_SITE_VALUES,
  KNOWN_ATTRIBUTES,
  MAX_COOKIE_LENGTH,
  sanitizeCookie,
  inspectSetCookie,
  applySetCookiePrefixGuard,
  describeReason,
};
