'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  OBSOLETE_HEADER: 'obsolete-header',
  MULTI_VALUE: 'multi-value',
  OVERLONG: 'overlong',
  MALFORMED: 'malformed',
};

const MAX_VALUE_LENGTH = 512;

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

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return 'Content-Base 状态正常';
    case REASON.MISSING:
      return '未声明 Content-Base';
    case REASON.OBSOLETE_HEADER:
      return 'Content-Base 已废弃，会改写相对 URL 基准';
    case REASON.MULTI_VALUE:
      return 'Content-Base 出现多个取值';
    case REASON.OVERLONG:
      return 'Content-Base 取值超长';
    case REASON.MALFORMED:
      return 'Content-Base 取值无法解析';
    default:
      return 'Content-Base 未知状态';
  }
}

module.exports = {
  REASON,
  inspectContentBase,
  applyContentBaseGuard,
  describeReason,
};
