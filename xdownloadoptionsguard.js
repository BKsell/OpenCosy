'use strict';
const { describeReasonFrom } = require('./reasontext');

const { hasControlCharsV2, listValues } = require('./modutil');
const hasControlChars = hasControlCharsV2;

const { deleteHeader, headerKey } = require('./headerutil');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  UNKNOWN_VALUE: 'unknown-value',
  MULTIPLE_VALUES: 'multiple-values',
  UNSAFE_CHARS: 'unsafe-chars',
};

const HEADER = 'x-download-options';
const SAFE_VALUE = 'noopen';
const MAX_VALUE_LENGTH = 64;

function inspectDownloadOptions(rawValues) {
  if (!Array.isArray(rawValues) || rawValues.length === 0) {
    return { reason: REASON.MISSING };
  }
  if (rawValues.length > 1) {
    return { reason: REASON.MULTIPLE_VALUES };
  }
  const text = rawValues[0].trim();
  if (!text) return { reason: REASON.MALFORMED };
  if (hasControlChars(text)) return { reason: REASON.UNSAFE_CHARS };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG };
  const lower = text.toLowerCase();
  if (lower === SAFE_VALUE) return { reason: REASON.OK };
  if (lower === 'open') return { reason: REASON.UNKNOWN_VALUE };
  return { reason: REASON.UNKNOWN_VALUE };
}

function describeReason(reason) {
  return describeReasonFrom({
    [REASON.OK]: 'x-download-options 合规',
    [REASON.MISSING]: '响应未声明 x-download-options',
    [REASON.MALFORMED]: 'x-download-options 取值为空',
    [REASON.OVERLONG]: 'x-download-options 超长',
    [REASON.UNKNOWN_VALUE]: 'x-download-options 非 noopen，已剥除',
    [REASON.MULTIPLE_VALUES]: 'x-download-options 多值冲突，已剥除',
    [REASON.UNSAFE_CHARS]: 'x-download-options 含控制字符，已剥除',
  }, reason, 'x-download-options 未识别状态');
}

function applyXDownloadOptionsGuard(headers) {
  const rawValues = values(headers, HEADER);
  if (rawValues.length === 0) {
    return { changed: false, reason: REASON.MISSING, findings: [] };
  }
  const result = inspectDownloadOptions(rawValues);
  const findings = [{ reason: result.reason }];
  if (result.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, findings };
  }
  deleteHeader(headers, HEADER);
  return { changed: true, reason: result.reason, findings };
}

module.exports = {
  REASON,
  HEADER,
  SAFE_VALUE,
  inspectDownloadOptions,
  applyXDownloadOptionsGuard,
  describeReason,
};
