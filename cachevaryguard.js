'use strict';

const REASON = Object.freeze({
  OK: 'ok',
  MISSING_VARY: 'missing-vary-origin',
  COOKIE_CACHEABLE: 'cookie-cacheable',
  PUBLIC_WITH_COOKIE: 'public-with-cookie',
});

function headerValues(headers, name) {
  if (!headers || typeof headers !== 'object') return [];
  const lower = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() !== lower) continue;
    const value = headers[key];
    if (Array.isArray(value)) return value.map((v) => String(v));
    if (value === undefined || value === null) return [];
    return [String(value)];
  }
  return [];
}

function setHeader(headers, name, values) {
  const lower = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) delete headers[key];
  }
  if (values && values.length) headers[name] = values;
}

function tokensOf(values) {
  const out = [];
  for (const value of values) {
    for (const token of String(value).split(',')) {
      const trimmed = token.trim();
      if (trimmed) out.push(trimmed);
    }
  }
  return out;
}

function evaluateCacheVary(headers) {
  const acao = headerValues(headers, 'Access-Control-Allow-Origin');
  const vary = tokensOf(headerValues(headers, 'Vary'));
  const cacheControl = tokensOf(headerValues(headers, 'Cache-Control')).map((t) => t.toLowerCase());
  const setCookie = headerValues(headers, 'Set-Cookie');
  const originScoped = acao.length === 1 && acao[0].trim() !== '*';

  if (originScoped && !vary.some((v) => v.toLowerCase() === 'origin')) {
    return {
      action: 'patch',
      reason: REASON.MISSING_VARY,
      addVary: true,
    };
  }

  if (setCookie.length) {
    const isPublic = cacheControl.includes('public');
    if (isPublic) {
      return {
        action: 'patch',
        reason: REASON.PUBLIC_WITH_COOKIE,
        cacheControl: 'private, no-store',
      };
    }
    if (!cacheControl.length || (!cacheControl.includes('no-store') && !cacheControl.includes('private'))) {
      return {
        action: 'patch',
        reason: REASON.COOKIE_CACHEABLE,
        cacheControl: 'private, no-store',
      };
    }
  }

  return { action: 'allow', reason: REASON.OK };
}

function applyCacheVaryGuard(headers) {
  const verdict = evaluateCacheVary(headers);
  if (verdict.action === 'allow') return { changed: false, verdict };
  const vary = tokensOf(headerValues(headers, 'Vary'));
  if (verdict.addVary && !vary.some((v) => v.toLowerCase() === 'origin')) {
    vary.push('Origin');
    setHeader(headers, 'Vary', [vary.join(', ')]);
  }
  if (verdict.cacheControl) setHeader(headers, 'Cache-Control', [verdict.cacheControl]);
  return { changed: true, verdict };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK: return '缓存键无需修补';
    case REASON.MISSING_VARY: return '按来源变化的响应缺少 Vary: Origin';
    case REASON.COOKIE_CACHEABLE: return '携带 Set-Cookie 的响应可被缓存';
    case REASON.PUBLIC_WITH_COOKIE: return '携带 Set-Cookie 却声明 public';
    default: return String(reason || '');
  }
}

module.exports = {
  REASON,
  evaluateCacheVary,
  applyCacheVaryGuard,
  describeReason,
};
