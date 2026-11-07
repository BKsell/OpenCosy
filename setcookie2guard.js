'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  OBSOLETE_HEADER: 'obsolete-header',
  MULTI_VALUE: 'multi-value',
  OVERSIZED_SET: 'oversized-set',
};

const MAX_SET_VALUES = 16;

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function countValues(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return 0;
  const raw = headers[key];
  if (Array.isArray(raw)) return raw.length;
  return typeof raw === 'string' ? 1 : 0;
}

function deleteHeader(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return false;
  delete headers[key];
  return true;
}

function applySetCookie2Guard(headers) {
  const key = headerKey(headers, 'set-cookie2');
  if (!key) return { changed: false, reason: REASON.MISSING };
  const raw = headers[key];
  const count = Array.isArray(raw) ? raw.length : 1;
  delete headers[key];
  if (count > MAX_SET_VALUES) {
    return { changed: true, reason: REASON.OVERSIZED_SET, count };
  }
  if (count > 1) {
    return { changed: true, reason: REASON.MULTI_VALUE, count };
  }
  return { changed: true, reason: REASON.OBSOLETE_HEADER, previous: raw };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return 'Set-Cookie2 状态正常';
    case REASON.MISSING:
      return '未声明 Set-Cookie2';
    case REASON.OBSOLETE_HEADER:
      return 'Set-Cookie2 已废弃，按 RFC 6265 应改用 Set-Cookie';
    case REASON.MULTI_VALUE:
      return 'Set-Cookie2 出现多条取值';
    case REASON.OVERSIZED_SET:
      return 'Set-Cookie2 条目数量异常';
    default:
      return 'Set-Cookie2 未知状态';
  }
}

module.exports = {
  REASON,
  applySetCookie2Guard,
  describeReason,
};
