'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  CROSS_ORIGIN: 'cross-origin',
  MALFORMED: 'malformed',
  BAD_SCHEME: 'bad-scheme',
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

function firstValue(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return '';
  const raw = headers[key];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === 'string' ? value : '';
}

function originOf(value) {
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return '';
    return parsed.origin;
  } catch {
    return '';
  }
}

function hasControlChars(value) {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

function inspectContentLocation(headers, details) {
  const value = firstValue(headers, 'content-location');
  if (!value) return { changed: false, reason: REASON.MISSING, target: '' };
  if (value.length > MAX_VALUE_LENGTH || hasControlChars(value)) {
    return { changed: true, reason: REASON.MALFORMED, target: '' };
  }
  const baseUrl = details && typeof details.url === 'string' ? details.url : '';
  let resolved = '';
  try {
    resolved = baseUrl ? new URL(value, baseUrl).href : value;
  } catch {
    resolved = '';
  }
  if (!originOf(resolved)) {
    return { changed: true, reason: REASON.BAD_SCHEME, target: value };
  }
  if (baseUrl && originOf(baseUrl) && originOf(resolved) !== originOf(baseUrl)) {
    return { changed: true, reason: REASON.CROSS_ORIGIN, target: value };
  }
  return { changed: false, reason: REASON.OK, target: resolved };
}

function applyContentLocationGuard(headers, details) {
  const result = inspectContentLocation(headers, details);
  if (!result.changed) return result;
  const key = headerKey(headers, 'content-location');
  if (key) delete headers[key];
  return result;
}

function describeReason(reason) {
  switch (reason) {
    case REASON.CROSS_ORIGIN:
      return 'Content-Location 指向其他源';
    case REASON.MALFORMED:
      return 'Content-Location 过长或含控制字符';
    case REASON.BAD_SCHEME:
      return 'Content-Location 使用非 HTTP(S) 目标';
    case REASON.MISSING:
      return '未声明 Content-Location';
    default:
      return 'Content-Location 与响应同源';
  }
}

module.exports = {
  REASON,
  MAX_VALUE_LENGTH,
  inspectContentLocation,
  applyContentLocationGuard,
  describeReason,
};
