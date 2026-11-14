'use strict';
const { describeReasonTable } = require('./reasontext');

const { deleteHeader, headerKey } = require('./headerutil_core');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  WEAK_MD5: 'weak-md5',
  MALFORMED_DIGEST: 'malformed-digest',
  OVERLONG: 'overlong',
};

const MAX_VALUE_LENGTH = 64;
const MD5_BASE64_PATTERN = /^[A-Za-z0-9+/]{22}==$/;

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

const describeReason = describeReasonTable({
    [REASON.OK]: 'Content-MD5 状态正常',
    [REASON.MISSING]: '未声明 Content-MD5',
    [REASON.WEAK_MD5]: 'Content-MD5 使用已弱的 MD5 摘要',
    [REASON.MALFORMED_DIGEST]: 'Content-MD5 摘要格式非法',
    [REASON.OVERLONG]: 'Content-MD5 取值超长',
  }, 'Content-MD5 未知状态');

module.exports = {
  REASON,
  inspectContentMd5,
  applyContentMd5Guard,
  describeReason,
};
