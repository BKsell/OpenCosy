'use strict';

const REASON = {
  OK: 'ok',
  FORBIDDEN_KEY: 'forbidden-key',
  TOO_DEEP: 'too-deep',
  TOO_MANY_KEYS: 'too-many-keys',
  TOO_LONG_STRING: 'too-long-string',
  TOO_MANY_ITEMS: 'too-many-items',
  UNSUPPORTED_TYPE: 'unsupported-type',
  NOT_FINITE: 'not-finite',
  CIRCULAR: 'circular',
};

const MAX_DEPTH = 4;
const MAX_KEYS = 32;
const MAX_STRING = 4096;
const MAX_ITEMS = 256;
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function checkNode(node, path, depth, seen) {
  if (depth > MAX_DEPTH) return { ok: false, reason: REASON.TOO_DEEP, path };
  if (node === null) return { ok: true };
  const type = typeof node;
  if (type === 'string') {
    if (node.length > MAX_STRING) return { ok: false, reason: REASON.TOO_LONG_STRING, path };
    return { ok: true };
  }
  if (type === 'number') {
    if (!Number.isFinite(node)) return { ok: false, reason: REASON.NOT_FINITE, path };
    return { ok: true };
  }
  if (type === 'boolean') return { ok: true };
  if (type !== 'object') return { ok: false, reason: REASON.UNSUPPORTED_TYPE, path };
  if (seen.has(node)) return { ok: false, reason: REASON.CIRCULAR, path };
  seen.add(node);
  if (Array.isArray(node)) {
    if (node.length > MAX_ITEMS) return { ok: false, reason: REASON.TOO_MANY_ITEMS, path };
    for (let i = 0; i < node.length; i += 1) {
      const child = checkNode(node[i], path + '[' + i + ']', depth + 1, seen);
      if (!child.ok) return child;
    }
    return { ok: true };
  }
  const keys = Object.keys(node);
  if (keys.length > MAX_KEYS) return { ok: false, reason: REASON.TOO_MANY_KEYS, path };
  for (const key of keys) {
    if (FORBIDDEN_KEYS.has(key)) return { ok: false, reason: REASON.FORBIDDEN_KEY, path: path + '.' + key };
    const child = checkNode(node[key], path + '.' + key, depth + 1, seen);
    if (!child.ok) return child;
  }
  return { ok: true };
}

function inspectPayload(payload) {
  const result = checkNode(payload, '$', 0, new Set());
  if (result.ok) return { ok: true, reason: REASON.OK, path: '$' };
  return { ok: false, reason: result.reason, path: result.path };
}

function applyIpcPayloadGuard(payload) {
  const result = inspectPayload(payload);
  if (!result.ok) return { changed: true, reason: result.reason, path: result.path };
  return { changed: false, reason: REASON.OK, path: '$' };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.FORBIDDEN_KEY:
      return 'IPC 负载包含原型污染键名';
    case REASON.TOO_DEEP:
      return 'IPC 负载嵌套层级过深';
    case REASON.TOO_MANY_KEYS:
      return 'IPC 负载对象键数量过多';
    case REASON.TOO_LONG_STRING:
      return 'IPC 负载字符串超长';
    case REASON.TOO_MANY_ITEMS:
      return 'IPC 负载数组元素过多';
    case REASON.UNSUPPORTED_TYPE:
      return 'IPC 负载包含不可序列化类型';
    case REASON.NOT_FINITE:
      return 'IPC 负载包含非有限数值';
    case REASON.CIRCULAR:
      return 'IPC 负载存在循环引用';
    default:
      return 'IPC 负载结构合法';
  }
}

module.exports = {
  REASON,
  MAX_DEPTH,
  MAX_KEYS,
  MAX_STRING,
  MAX_ITEMS,
  FORBIDDEN_KEYS,
  inspectPayload,
  applyIpcPayloadGuard,
  describeReason,
};
