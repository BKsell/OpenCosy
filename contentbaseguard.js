'use strict';
const { describeReasonTable } = require('./reasontext');

const { countValues, deleteHeader, headerKey } = require('./headerutil');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  OBSOLETE_HEADER: 'obsolete-header',
  MULTI_VALUE: 'multi-value',
  OVERLONG: 'overlong',
  MALFORMED: 'malformed',
};

const MAX_VALUE_LENGTH = 512;

function inspectContentBase(value) {
  if (value === undefined || value === null) return { reason: REASON.MISSING };
  if (typeof value !== 'string') return { reason: REASON.MALFORMED };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG };
  return { reason: REASON.OBSOLETE_HEADER, value: text };
}

function applyContentBaseGuard(headers) {
  const key = headerKey(headers, 'content-base');
  if (!key) return { changed: false, reason: REASON.MISSING };
  const raw = headers[key];
  if (Array.isArray(raw) && raw.length > 1) {
    delete headers[key];
    return { changed: true, reason: REASON.MULTI_VALUE, previous: raw.slice(0, 4) };
  }
  const value = Array.isArray(raw) ? raw[0] : raw;
  const verdict = inspectContentBase(value);
  delete headers[key];
  return { changed: true, reason: verdict.reason, previous: value };
}

const describeReason = describeReasonTable({
    [REASON.OK]: 'Content-Base 状态正常',
    [REASON.MISSING]: '未声明 Content-Base',
    [REASON.OBSOLETE_HEADER]: 'Content-Base 已废弃，会改写相对 URL 基准',
    [REASON.MULTI_VALUE]: 'Content-Base 出现多个取值',
    [REASON.OVERLONG]: 'Content-Base 取值超长',
    [REASON.MALFORMED]: 'Content-Base 取值无法解析',
  }, 'Content-Base 未知状态');

module.exports = {
  REASON,
  inspectContentBase,
  applyContentBaseGuard,
  describeReason,
};
