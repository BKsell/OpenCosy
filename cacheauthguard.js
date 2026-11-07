'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  AUTH_CACHEABLE: 'auth-response-cacheable',
  SHARED_CACHE: 'shared-cache-leak',
  MALFORMED: 'malformed',
};

const MAX_VALUE_LENGTH = 512;

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function headerText(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return '';
  const raw = headers[key];
  const value = Array.isArray(raw) ? raw.join(', ') : raw;
  return typeof value === 'string' ? value : '';
}

function cacheDirectives(value) {
  return value
    .split(',')
    .map((part) => part.trim().toLowerCase())
    .filter(Boolean);
}

function hasPrivateScope(directives) {
  return directives.some((see) => see === 'private' || see.startsWith('private='));
}

function hasNoStore(directives) {
  return directives.includes('no-store');
}

function hasSharedCaching(directives) {
  return directives.some((directive) => {
    if (directive === 'public') return true;
    if (directive.startsWith('s-maxage')) return true;
    if (directive.startsWith('max-age')) {
      const eq = directive.indexOf('=');
      const seconds = Number(directive.slice(eq + 1).trim());
      return Number.isFinite(seconds) && seconds > 0;
    }
    return false;
  });
}

function saysCacheable(directives) {
  return directives.includes('no-cache') || directives.includes('no-store');
}

function inspectAuthCache(headers) {
  const key = headerKey(headers, 'cache-control');
  const setCookie = headerText(headers, 'set-cookie');
  const authChallenge = headerText(headers, 'www-authenticate');
  const raw = headerText(headers, 'cache-control').trim();
  if (!key) {
    if (setCookie) {
      return { changed: true, reason: REASON.MISSING, value: '', sensitive: true };
    }
    return { changed: false, reason: REASON.MISSING, value: '', sensitive: false };
  }
  if (raw.length > MAX_VALUE_LENGTH) {
    return { changed: true, reason: REASON.MALFORMED, value: raw, sensitive: !!setCookie };
  }
  const directives = cacheDirectives(raw);
  if (!directives.length) {
    return { changed: true, reason: REASON.MALFORMED, value: raw, sensitive: !!setCookie };
  }
  const sensitive = !!setCookie || !!authChallenge || directives.includes('private');
  if (!sensitive) {
    if (hasSharedCaching(directives) && !saysCacheable(directives)) {
      return { changed: false, reason: REASON.OK, value: raw, sensitive: false };
    }
    return { changed: false, reason: REASON.OK, value: raw, sensitive: false };
  }
  if (hasNoStore(directives)) {
    return { changed: false, reason: REASON.OK, value: raw, sensitive: true };
  }
  if (hasSharedCaching(directives)) {
    return { changed: true, reason: REASON.SHARED_CACHE, value: raw, sensitive: true };
  }
  if (!hasPrivateScope(directives)) {
    return { changed: true, reason: REASON.AUTH_CACHEABLE, value: raw, sensitive: true };
  }
  return { changed: false, reason: REASON.OK, value: raw, sensitive: true };
}

function applyAuthCacheGuard(headers) {
  const result = inspectAuthCache(headers);
  if (!result.changed) return result;
  headers['cache-control'] = ['private, no-store, max-age=0'];
  const stale = headerKey(headers, 'expires');
  if (stale) headers[stale] = ['Thu, 01 Jan 1970 00:00:00 GMT'];
  const age = headerKey(headers, 'age');
  if (age) delete headers[age];
  return result;
}

function describeReason(reason) {
  switch (reason) {
    case REASON.AUTH_CACHEABLE:
      return '携带凭据的响应缺少 private/no-store';
    case REASON.SHARED_CACHE:
      return '携带凭据的响应允许共享缓存';
    case REASON.MALFORMED:
      return 'Cache-Control 取值非法或超长';
    case REASON.MISSING:
      return '携带 Set-Cookie 的响应完全没有缓存指令';
    default:
      return '缓存策略安全';
  }
}

module.exports = {
  REASON,
  MAX_VALUE_LENGTH,
  cacheDirectives,
  inspectAuthCache,
  applyAuthCacheGuard,
  describeReason,
};
