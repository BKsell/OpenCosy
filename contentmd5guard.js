'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  WEAK_MD5: 'weak-md5',
  MALFORMED_DIGEST: 'malformed-digest',
  OVERLONG: 'overlong',
};

const MAX_VALUE_LENGTH = 64;
const MD5_BASE64_PATTERN = /^[A-Za-z0-9+/]{22}==$/;

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

function inspectContentMd5(value) {
  if (value === undefined || value === null) return { reason: REASON.MISSING };
  if (typeof value !== 'string') return { reason: REASON.MALFORMED_DIGEST };
  const text = value.trim();
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG };
  if (!MD5_BASE64_PATTERN.test(text)) return { reason: REASON.MALFORMED_DIGEST, value: text };
  return { reason: REASON.WEAK_MD5, value: text };
}

function applyContentMd5Guard(headers) {
  const key = headerKey(headers, 'content-md5');
  if (!key) return { changed: false, reason: REASON.MISSING };
  const raw = headers[key];
  const value = Array.isArray(raw) ? raw[0] : raw;
  const verdict = inspectContentMd5(value);
  delete headers[key];
  return { changed: true, reason: verdict.reason, previous: value };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return 'Content-MD5 状态正常';
    case REASON.MISSING:
      return '未声明 Content-MD5';
    case REASON.WEAK_MD5:
      return 'Content-MD5 使用已弱的 MD5 摘要';
    case REASON.MALFORMED_DIGEST:
      return 'Content-MD5 摘要格式非法';
    case REASON.OVERLONG:
      return 'Content-MD5 取值超长';
    default:
      return 'Content-MD5 未知状态';
  }
}

module.exports = {
  REASON,
  inspectContentMd5,
  applyContentMd5Guard,
  describeReason,
};
