'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'empty-headers',
  TOO_MANY: 'too-many-headers',
  TOO_LARGE: 'budget-exceeded',
  OVERSIZE_VALUE: 'oversize-value',
  EMPTY_NAME: 'empty-name',
};

const MAX_HEADER_COUNT = 96;
const MAX_TOTAL_BYTES = 32 * 1024;
const MAX_VALUE_BYTES = 8 * 1024;
const MAX_NAME_BYTES = 64;

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function byteLength(value) {
  if (typeof value !== 'string') return 0;
  let bytes = 0;
  for (const ch of value) {
    const code = ch.codePointAt(0);
    if (code <= 0x7f) bytes += 1;
    else if (code <= 0x7ff) bytes += 2;
    else if (code <= 0xffff) bytes += 3;
    else bytes += 4;
  }
  return bytes;
}

function inspectHeaderBudget(headers) {
  if (!headers || typeof headers !== 'object') {
    return { changed: false, reason: REASON.EMPTY, count: 0, bytes: 0 };
  }
  const keys = Object.keys(headers);
  if (keys.length === 0) {
    return { changed: false, reason: REASON.EMPTY, count: 0, bytes: 0 };
  }
  if (keys.length > MAX_HEADER_COUNT) {
    return { changed: true, reason: REASON.TOO_MANY, count: keys.length, bytes: 0 };
  }
  let total = 0;
  let oversize = false;
  let emptyName = false;
  for (const key of keys) {
    if (!key || key.trim() === '') emptyName = true;
    total += byteLength(key) + 2;
    const raw = headers[key];
    const values = Array.isArray(raw) ? raw : [raw];
    for (const value of values) {
      if (typeof value !== 'string') continue;
      total += byteLength(value) + 2;
      if (byteLength(value) > MAX_VALUE_BYTES) oversize = true;
    }
  }
  if (emptyName) {
    return { changed: true, reason: REASON.EMPTY_NAME, count: keys.length, bytes: total };
  }
  if (oversize) {
    return { changed: true, reason: REASON.OVERSIZE_VALUE, count: keys.length, bytes: total };
  }
  if (total > MAX_TOTAL_BYTES) {
    return { changed: true, reason: REASON.TOO_LARGE, count: keys.length, bytes: total };
  }
  return { changed: false, reason: REASON.OK, count: keys.length, bytes: total };
}

function oversizedHeaderKeys(headers) {
  const found = [];
  if (!headers || typeof headers !== 'object') return found;
  for (const key of Object.keys(headers)) {
    const raw = headers[key];
    const values = Array.isArray(raw) ? raw : [raw];
    for (const value of values) {
      if (typeof value === 'string' && byteLength(value) > MAX_VALUE_BYTES) {
        found.push(key);
        break;
      }
    }
  }
  return found;
}

function applyHeaderBudgetGuard(headers) {
  const result = inspectHeaderBudget(headers);
  if (!result.changed) return result;
  if (result.reason !== REASON.OVERSIZE_VALUE) return result;
  for (const key of oversizedHeaderKeys(headers)) {
    delete headers[key];
  }
  return result;
}

function describeReason(reason) {
  switch (reason) {
    case REASON.TOO_MANY:
      return '响应头数量超过预算';
    case REASON.TOO_LARGE:
      return '响应头总字节数超过预算';
    case REASON.OVERSIZE_VALUE:
      return '单个响应头取值超过预算，已剥除';
    case REASON.EMPTY_NAME:
      return '响应头存在空名称';
    default:
      return '响应头体积在预算内';
  }
}

module.exports = {
  REASON,
  MAX_HEADER_COUNT,
  MAX_TOTAL_BYTES,
  MAX_VALUE_BYTES,
  MAX_NAME_BYTES,
  headerKey,
  byteLength,
  inspectHeaderBudget,
  oversizedHeaderKeys,
  applyHeaderBudgetGuard,
  describeReason,
};
