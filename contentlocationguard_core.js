'use strict';
const { describeReasonTable } = require('./reasontext');
const { originOf, hasControlChars } = require('./modutil');

const { firstValue, headerKey } = require('./headerutil');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  CROSS_ORIGIN: 'cross-origin',
  MALFORMED: 'malformed',
  BAD_SCHEME: 'bad-scheme',
};

const MAX_VALUE_LENGTH = 512;

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

const describeReason = describeReasonTable({
    [REASON.CROSS_ORIGIN]: 'Content-Location 指向其他源',
    [REASON.MALFORMED]: 'Content-Location 过长或含控制字符',
    [REASON.BAD_SCHEME]: 'Content-Location 使用非 HTTP(S) 目标',
    [REASON.MISSING]: '未声明 Content-Location',
  }, 'Content-Location 与响应同源');

module.exports = {
  REASON,
  MAX_VALUE_LENGTH,
  inspectContentLocation,
  applyContentLocationGuard,
  describeReason,
};
