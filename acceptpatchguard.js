'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  WILDCARD: 'wildcard-accepted',
  UNSAFE_TYPE: 'unsafe-media-type',
  UNKNOWN_TYPE: 'unknown-media-type',
  DUPLICATE: 'duplicate-media-type',
};

const HEADER = 'accept-patch';
const MAX_VALUE_LENGTH = 512;
const ALLOWED_TYPES = new Set([
  'application/json-patch+json',
  'application/merge-patch+json',
  'application/ld+json',
  'application/apply-patch+yaml',
  'text/plain',
]);

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

function deleteHeader(headers, name) {
  const key = headerKey(headers, name);
  if (key) delete headers[key];
}

function normalizeType(token) {
  const text = token.trim().toLowerCase();
  if (!text) return '';
  const semi = text.indexOf(';');
  return (semi >= 0 ? text.slice(0, semi) : text).trim();
}

function inspectAcceptPatch(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, types: [] };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED, types: [] };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG, types: [] };

  const seen = new Set();
  const kept = [];
  let reason = REASON.OK;
  const note = (next) => {
    if (reason === REASON.OK) reason = next;
  };

  for (const raw of text.split(',')) {
    const type = normalizeType(raw);
    if (!type) continue;
    if (type === '*' || type === '*/*' || type === 'application/*') {
      note(REASON.WILDCARD);
      continue;
    }
    if (type.includes('html') || type.includes('xml') || type.includes('javascript')) {
      note(REASON.UNSAFE_TYPE);
      continue;
    }
    if (!ALLOWED_TYPES.has(type)) {
      note(REASON.UNKNOWN_TYPE);
      continue;
    }
    if (seen.has(type)) {
      note(REASON.DUPLICATE);
      continue;
    }
    seen.add(type);
    kept.push(type);
  }

  if (kept.length === 0 && reason !== REASON.OK) return { reason, types: [] };
  return { reason, types: kept };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return 'accept-patch 合规';
    case REASON.MISSING:
      return '响应未声明 accept-patch';
    case REASON.MALFORMED:
      return 'accept-patch 取值非法';
    case REASON.OVERLONG:
      return 'accept-patch 超长';
    case REASON.WILDCARD:
      return 'accept-patch 接受通配补丁类型，已剔除';
    case REASON.UNSAFE_TYPE:
      return 'accept-patch 接受可执行或可渲染类型，已剔除';
    case REASON.UNKNOWN_TYPE:
      return 'accept-patch 类型不在白名单，已剔除';
    case REASON.DUPLICATE:
      return 'accept-patch 重复类型已去重';
    default:
      return 'accept-patch 未识别状态';
  }
}

function applyAcceptPatchGuard(headers) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING, types: [] };
  const result = inspectAcceptPatch(value);
  if (result.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, types: result.types };
  }
  if (result.types.length === 0) {
    deleteHeader(headers, HEADER);
  } else {
    headers[headerKey(headers, HEADER)] = [result.types.join(', ')];
  }
  return { changed: true, reason: result.reason, types: result.types };
}

module.exports = {
  REASON,
  HEADER,
  inspectAcceptPatch,
  applyAcceptPatchGuard,
  describeReason,
};
