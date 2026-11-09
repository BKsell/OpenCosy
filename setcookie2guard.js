'use strict';
const { describeReasonFrom } = require('./reasontext');

const { countValues, deleteHeader, headerKey } = require('./headerutil');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  OBSOLETE_HEADER: 'obsolete-header',
  MULTI_VALUE: 'multi-value',
  OVERSIZED_SET: 'oversized-set',
};

const MAX_SET_VALUES = 16;

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
  return describeReasonFrom({
    [REASON.OK]: 'Set-Cookie2 状态正常',
    [REASON.MISSING]: '未声明 Set-Cookie2',
    [REASON.OBSOLETE_HEADER]: 'Set-Cookie2 已废弃，按 RFC 6265 应改用 Set-Cookie',
    [REASON.MULTI_VALUE]: 'Set-Cookie2 出现多条取值',
    [REASON.OVERSIZED_SET]: 'Set-Cookie2 条目数量异常',
  }, reason, 'Set-Cookie2 未知状态');
}

module.exports = {
  REASON,
  applySetCookie2Guard,
  describeReason,
};
