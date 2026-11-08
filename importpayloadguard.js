'use strict';

const REASON = {
  OK: 'ok',
  INVALID_INPUT: 'invalid-input',
  TOO_LARGE: 'too-large',
  PARSE_ERROR: 'parse-error',
  TOO_DEEP: 'too-deep',
  TOO_MANY_ENTRIES: 'too-many-entries',
  TOO_LONG_STRING: 'too-long-string',
  FORBIDDEN_KEY: 'forbidden-key',
  NOT_FINITE: 'not-finite',
};

const MAX_BYTES = 2 * 1024 * 1024;
const MAX_DEPTH = 8;
const MAX_ENTRIES = 100000;
const MAX_STRING = 1024 * 1024;
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function walk(value, depth, state) {
  if (state.entries > MAX_ENTRIES) return REASON.TOO_MANY_ENTRIES;
  if (depth > MAX_DEPTH) return REASON.TOO_DEEP;
  if (value === null) return REASON.OK;
  const type = typeof value;
  if (type === 'string') {
    if (value.length > MAX_STRING) return REASON.TOO_LONG_STRING;
    return REASON.OK;
  }
  if (type === 'number') return Number.isFinite(value) ? REASON.OK : REASON.NOT_FINITE;
  if (type === 'boolean') return REASON.OK;
  if (type !== 'object') return REASON.INVALID_INPUT;
  if (Array.isArray(value)) {
    for (const item of value) {
      state.entries += 1;
      const reason = walk(item, depth + 1, state);
      if (reason !== REASON.OK) return reason;
    }
    return REASON.OK;
  }
  for (const key of Object.keys(value)) {
    state.entries += 1;
    if (FORBIDDEN_KEYS.has(key)) return REASON.FORBIDDEN_KEY;
    if (key.length > MAX_STRING) return REASON.TOO_LONG_STRING;
    const reason = walk(value[key], depth + 1, state);
    if (reason !== REASON.OK) return reason;
  }
  return REASON.OK;
}

function parseImportPayload(text) {
  if (typeof text !== 'string') return { ok: false, value: null, reason: REASON.INVALID_INPUT, bytes: 0 };
  const bytes = Buffer.byteLength(text, 'utf8');
  if (bytes > MAX_BYTES) return { ok: false, value: null, reason: REASON.TOO_LARGE, bytes };
  let value;
  try {
    value = JSON.parse(text);
  } catch (err) {
    return { ok: false, value: null, reason: REASON.PARSE_ERROR, bytes };
  }
  const reason = walk(value, 0, { entries: 0 });
  if (reason !== REASON.OK) return { ok: false, value: null, reason, bytes };
  return { ok: true, value, reason: REASON.OK, bytes };
}

function applyImportPayloadGuard(text) {
  const result = parseImportPayload(text);
  if (!result.ok) return { changed: true, reason: result.reason, value: null };
  return { changed: false, reason: REASON.OK, value: result.value };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.INVALID_INPUT:
      return '导入内容不是文本';
    case REASON.TOO_LARGE:
      return '导入文件超过体积上限';
    case REASON.PARSE_ERROR:
      return '导入文件不是合法 JSON';
    case REASON.TOO_DEEP:
      return '导入 JSON 嵌套层级过深';
    case REASON.TOO_MANY_ENTRIES:
      return '导入 JSON 节点数量过多';
    case REASON.TOO_LONG_STRING:
      return '导入 JSON 字符串超长';
    case REASON.FORBIDDEN_KEY:
      return '导入 JSON 包含原型污染键名';
    case REASON.NOT_FINITE:
      return '导入 JSON 包含非有限数值';
    default:
      return '导入 JSON 结构合法';
  }
}

module.exports = {
  REASON,
  MAX_BYTES,
  MAX_DEPTH,
  MAX_ENTRIES,
  MAX_STRING,
  parseImportPayload,
  applyImportPayloadGuard,
  describeReason,
};
