'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  UNKNOWN_DIRECTIVE: 'unknown-directive',
  BAD_RANGE: 'bad-range',
  MULTI_VALUE: 'multi-value',
  OVERLONG: 'overlong',
  MALFORMED: 'malformed',
};

const MAX_VALUE_LENGTH = 256;
const MAX_AGE_LIMIT = 86400;
const STALE_LIMIT = 604800;
const ALLOWED = new Set(['no-store', 'no-cache', 'max-age', 'stale-while-revalidate', 'stale-if-error']);

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function deleteHeader(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return false;
  delete headers[key];
  return true;
}

function inspectSurrogateControl(value) {
  if (value === undefined || value === null) return { reason: REASON.MISSING };
  if (typeof value !== 'string') return { reason: REASON.MALFORMED };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG };
  if (text.includes(',') && /\d,\s*\d/.test(text)) return { reason: REASON.MULTI_VALUE };
  const parts = text.split(',').map((item) => item.trim()).filter(Boolean);
  if (parts.length === 0) return { reason: REASON.MALFORMED };
  const directives = {};
  for (const part of parts) {
    const split = part.split('=');
    const name = split[0].trim().toLowerCase();
    const rawValue = split.slice(1).join('=').trim();
    if (!ALLOWED.has(name)) {
      return { reason: REASON.UNKNOWN_DIRECTIVE, directive: name.slice(0, 32) };
    }
    if (name === 'no-store' || name === 'no-cache') {
      directives[name] = true;
      continue;
    }
    const numeric = Number(rawValue);
    if (!Number.isInteger(numeric) || rawValue === '') {
      return { reason: REASON.BAD_RANGE, directive: part.slice(0, 48) };
    }
    const limit = name === 'max-age' ? MAX_AGE_LIMIT : STALE_LIMIT;
    if (numeric < 0 || numeric > limit) {
      return { reason: REASON.BAD_RANGE, directive: part.slice(0, 48) };
    }
    directives[name] = numeric;
  }
  if (directives['no-store']) {
    return { reason: REASON.OK, canonical: 'no-store', directives };
  }
  const ordered = [];
  if (directives['no-cache']) ordered.push('no-cache');
  if (directives['max-age'] !== undefined) ordered.push(`max-age=${directives['max-age']}`);
  if (directives['stale-while-revalidate'] !== undefined) {
    ordered.push(`stale-while-revalidate=${directives['stale-while-revalidate']}`);
  }
  if (directives['stale-if-error'] !== undefined) {
    ordered.push(`stale-if-error=${directives['stale-if-error']}`);
  }
  return { reason: REASON.OK, canonical: ordered.join(', '), directives };
}

function applySurrogateControlGuard(headers) {
  const key = headerKey(headers, 'surrogate-control');
  if (!key) return { changed: false, reason: REASON.MISSING };
  const raw = headers[key];
  if (Array.isArray(raw) && raw.length > 1) {
    delete headers[key];
    return { changed: true, reason: REASON.MULTI_VALUE, previous: raw.slice(0, 4) };
  }
  const value = Array.isArray(raw) ? raw[0] : raw;
  const verdict = inspectSurrogateControl(value);
  if (verdict.reason !== REASON.OK) {
    delete headers[key];
    return { changed: true, reason: verdict.reason, directive: verdict.directive || null };
  }
  if (verdict.canonical === value) {
    return { changed: false, reason: REASON.OK, canonical: verdict.canonical };
  }
  headers[key] = verdict.canonical;
  return { changed: true, reason: REASON.OK, canonical: verdict.canonical };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return 'Surrogate-Control 已收敛为 CDN 安全指令';
    case REASON.MISSING:
      return '未声明 Surrogate-Control';
    case REASON.UNKNOWN_DIRECTIVE:
      return 'Surrogate-Control 使用未知指令';
    case REASON.BAD_RANGE:
      return 'Surrogate-Control 缓存时长越界';
    case REASON.MULTI_VALUE:
      return 'Surrogate-Control 出现多个取值';
    case REASON.OVERLONG:
      return 'Surrogate-Control 取值超长';
    case REASON.MALFORMED:
      return 'Surrogate-Control 取值无法解析';
    default:
      return 'Surrogate-Control 未知状态';
  }
}

module.exports = {
  REASON,
  inspectSurrogateControl,
  applySurrogateControlGuard,
  describeReason,
};
