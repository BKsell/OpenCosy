'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'empty',
  MALFORMED: 'malformed',
  CONTROL: 'control-characters',
  TOO_LONG: 'too-long',
  DOMAIN_MISMATCH: 'domain-mismatch',
  PUBLIC_SUFFIX: 'public-suffix-domain',
  PREFIX_REQUIRES_SECURE: 'prefix-requires-secure',
  PREFIX_REQUIRES_HOST_ONLY: 'prefix-requires-host-only',
  SAMESITE_NONE_INSECURE: 'samesite-none-insecure',
  BAD_MAX_AGE: 'bad-max-age',
};

const MAX_COOKIE_LENGTH = 4096;
const MAX_AGE_SECONDS = 400 * 24 * 3600;
const PUBLIC_SUFFIXES = new Set(['com', 'org', 'net', 'edu', 'gov', 'io', 'co', 'cn', 'uk', 'jp', 'de', 'fr', 'ru', 'br', 'in', 'au', 'ca']);
const IPV4 = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

function hasControlChars(value) {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

function parseSetCookie(value) {
  if (typeof value !== 'string' || !value.trim()) return { ok: false, reason: REASON.EMPTY };
  if (value.length > MAX_COOKIE_LENGTH) return { ok: false, reason: REASON.TOO_LONG };
  if (hasControlChars(value)) return { ok: false, reason: REASON.CONTROL };
  const parts = value.split(';');
  const pair = parts[0].trim();
  const eq = pair.indexOf('=');
  if (eq <= 0) return { ok: false, reason: REASON.MALFORMED };
  const name = pair.slice(0, eq).trim();
  if (!name) return { ok: false, reason: REASON.MALFORMED };
  const attributes = {};
  for (let i = 1; i < parts.length; i += 1) {
    const attribute = parts[i].trim();
    if (!attribute) continue;
    const attrEq = attribute.indexOf('=');
    const key = (attrEq < 0 ? attribute : attribute.slice(0, attrEq)).trim().toLowerCase();
    const val = attrEq < 0 ? true : attribute.slice(attrEq + 1).trim();
    if (key === 'domain' || key === 'path' || key === 'max-age' || key === 'expires' || key === 'samesite') {
      attributes[key] = val;
    } else if (key === 'secure' || key === 'httponly') {
      attributes[key] = true;
    }
  }
  return { ok: true, name, attributes };
}

function inspectSetCookie(value, requestHost) {
  const parsed = parseSetCookie(value);
  if (!parsed.ok) return { ok: false, reason: parsed.reason };
  const host = typeof requestHost === 'string' ? requestHost.trim().toLowerCase() : '';
  if (!host) return { ok: false, reason: REASON.DOMAIN_MISMATCH };
  const attributes = parsed.attributes;
  const secure = attributes.secure === true;
  if (parsed.name.startsWith('__Host-')) {
    if (!secure) return { ok: false, reason: REASON.PREFIX_REQUIRES_SECURE };
    if (attributes.domain !== undefined) return { ok: false, reason: REASON.PREFIX_REQUIRES_HOST_ONLY };
    if (String(attributes.path || '') !== '/') return { ok: false, reason: REASON.PREFIX_REQUIRES_HOST_ONLY };
  }
  if (parsed.name.startsWith('__Secure-') && !secure) return { ok: false, reason: REASON.PREFIX_REQUIRES_SECURE };
  if (typeof attributes.samesite === 'string' && attributes.samesite.toLowerCase() === 'none' && !secure) {
    return { ok: false, reason: REASON.SAMESITE_NONE_INSECURE };
  }
  if (typeof attributes['max-age'] === 'string') {
    if (!/^-?\d{1,12}$/.test(attributes['max-age'])) return { ok: false, reason: REASON.BAD_MAX_AGE };
    const seconds = Number(attributes['max-age']);
    if (seconds > MAX_AGE_SECONDS) return { ok: false, reason: REASON.BAD_MAX_AGE };
  }
  if (typeof attributes.domain === 'string') {
    const domain = attributes.domain.replace(/^\./, '').toLowerCase();
    if (!domain) return { ok: false, reason: REASON.DOMAIN_MISMATCH };
    if (PUBLIC_SUFFIXES.has(domain) || IPV4.test(domain)) return { ok: false, reason: REASON.PUBLIC_SUFFIX };
    if (domain !== host && !host.endsWith('.' + domain)) return { ok: false, reason: REASON.DOMAIN_MISMATCH };
  }
  return { ok: true, reason: REASON.OK, name: parsed.name, attributes };
}

function applyCookieDomainGuard(value, requestHost) {
  const result = inspectSetCookie(value, requestHost);
  return { changed: !result.ok, reason: result.reason, name: result.name || '' };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.EMPTY:
      return 'Set-Cookie 为空';
    case REASON.MALFORMED:
      return 'Set-Cookie 格式非法';
    case REASON.CONTROL:
      return 'Set-Cookie 含控制字符';
    case REASON.TOO_LONG:
      return 'Set-Cookie 超过长度上限';
    case REASON.DOMAIN_MISMATCH:
      return 'Cookie 域与响应主机不匹配';
    case REASON.PUBLIC_SUFFIX:
      return 'Cookie 域为公共后缀或 IP';
    case REASON.PREFIX_REQUIRES_SECURE:
      return '前缀 Cookie 缺少 Secure';
    case REASON.PREFIX_REQUIRES_HOST_ONLY:
      return '__Host- Cookie 设置了域或非根路径';
    case REASON.SAMESITE_NONE_INSECURE:
      return 'SameSite=None 缺少 Secure';
    case REASON.BAD_MAX_AGE:
      return 'Cookie 有效期非法或过长';
    default:
      return 'Set-Cookie 属性合法';
  }
}

module.exports = {
  REASON,
  MAX_COOKIE_LENGTH,
  MAX_AGE_SECONDS,
  PUBLIC_SUFFIXES,
  parseSetCookie,
  inspectSetCookie,
  applyCookieDomainGuard,
  describeReason,
};
