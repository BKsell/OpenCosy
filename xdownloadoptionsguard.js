'use strict';

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

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function values(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return [];
  const raw = headers[key];
  if (Array.isArray(raw)) return raw.filter((item) => typeof item === 'string');
  return typeof raw === 'string' ? [raw] : [];
}

function deleteHeader(headers, name) {
  const key = headerKey(headers, name);
  if (key) delete headers[key];
}

function hasControlChars(text) {
  for (const ch of text) {
    const code = ch.charCodeAt(0);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

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
  switch (reason) {
    case REASON.OK:
      return 'x-download-options 合规';
    case REASON.MISSING:
      return '响应未声明 x-download-options';
    case REASON.MALFORMED:
      return 'x-download-options 取值为空';
    case REASON.OVERLONG:
      return 'x-download-options 超长';
    case REASON.UNKNOWN_VALUE:
      return 'x-download-options 非 noopen，已剥除';
    case REASON.MULTIPLE_VALUES:
      return 'x-download-options 多值冲突，已剥除';
    case REASON.UNSAFE_CHARS:
      return 'x-download-options 含控制字符，已剥除';
    default:
      return 'x-download-options 未识别状态';
  }
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
