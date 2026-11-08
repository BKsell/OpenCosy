'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  NONE_ONLY: 'none-only',
  UNKNOWN_UNIT: 'unknown-unit',
  MULTI_VALUE: 'multi-value',
  OVERLONG: 'overlong',
  UNBACKED_BYTES: 'unbacked-bytes',
  MALFORMED: 'malformed',
};

const MAX_VALUE_LENGTH = 48;
const UNIT_PATTERN = /^(none|bytes|items)$/i;

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
  if (!key) return false;
  delete headers[key];
  return true;
}

function hasByteEvidence(headers) {
  return Boolean(headerKey(headers, 'content-length')) || Boolean(headerKey(headers, 'content-range'));
}

function inspectAcceptRanges(value, headers) {
  if (value === undefined || value === null) return { reason: REASON.MISSING };
  if (typeof value !== 'string') return { reason: REASON.MALFORMED };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG };
  if (text.includes(',')) return { reason: REASON.MULTI_VALUE };
  const match = UNIT_PATTERN.exec(text);
  if (!match) return { reason: REASON.UNKNOWN_UNIT };
  const unit = match[1].toLowerCase();
  if (unit === 'none') return { reason: REASON.NONE_ONLY, unit };
  if (unit === 'items') return { reason: REASON.UNKNOWN_UNIT, unit };
  if (!hasByteEvidence(headers)) return { reason: REASON.UNBACKED_BYTES, unit };
  return { reason: REASON.OK, unit };
}

function applyAcceptRangesGuard(headers) {
  const key = headerKey(headers, 'accept-ranges');
  if (!key) return { changed: false, reason: REASON.MISSING };
  const raw = headers[key];
  if (Array.isArray(raw) && raw.length > 1) {
    delete headers[key];
    return { changed: true, reason: REASON.MULTI_VALUE, previous: raw.slice(0, 4) };
  }
  const value = Array.isArray(raw) ? raw[0] : raw;
  const verdict = inspectAcceptRanges(value, headers);
  if (verdict.reason === REASON.OK || verdict.reason === REASON.NONE_ONLY) {
    return { changed: false, reason: verdict.reason, unit: verdict.unit };
  }
  delete headers[key];
  return { changed: true, reason: verdict.reason, unit: verdict.unit || null };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return 'Accept-Ranges 支持字节范围';
    case REASON.MISSING:
      return '未声明 Accept-Ranges';
    case REASON.NONE_ONLY:
      return 'Accept-Ranges 声明不支持范围请求';
    case REASON.UNKNOWN_UNIT:
      return 'Accept-Ranges 使用未知单位';
    case REASON.MULTI_VALUE:
      return 'Accept-Ranges 出现多个取值';
    case REASON.OVERLONG:
      return 'Accept-Ranges 取值超长';
    case REASON.UNBACKED_BYTES:
      return 'Accept-Ranges 声称 bytes 但缺少长度证据';
    case REASON.MALFORMED:
      return 'Accept-Ranges 取值无法解析';
    default:
      return 'Accept-Ranges 未知状态';
  }
}

module.exports = {
  REASON,
  inspectAcceptRanges,
  applyAcceptRangesGuard,
  describeReason,
};
