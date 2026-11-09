'use strict';
const { describeReasonFrom } = require('./reasontext');

const REASON = {
  OK: 'ok',
  UNSUPPORTED_TYPE: 'unsupported-type',
  NOT_FINITE: 'not-finite',
  CIRCULAR: 'circular',
  TOO_DEEP: 'too-deep',
  TOO_LARGE: 'too-large',
  SERIALIZE_FAILED: 'serialize-failed',
};

const MAX_JSON_BYTES = 32768;
const MAX_DEPTH = 5;
const MAX_ITEMS = 512;

function collect(value, depth, seen) {
  if (depth > MAX_DEPTH) return REASON.TOO_DEEP;
  if (value === null) return REASON.OK;
  const type = typeof value;
  if (type === 'string' || type === 'boolean') return REASON.OK;
  if (type === 'number') return Number.isFinite(value) ? REASON.OK : REASON.NOT_FINITE;
  if (type !== 'object') return REASON.UNSUPPORTED_TYPE;
  if (seen.has(value)) return REASON.CIRCULAR;
  seen.add(value);
  if (Array.isArray(value)) {
    if (value.length > MAX_ITEMS) return REASON.TOO_LARGE;
    for (const item of value) {
      const reason = collect(item, depth + 1, seen);
      if (reason !== REASON.OK) return reason;
    }
    return REASON.OK;
  }
  for (const key of Object.keys(value)) {
    const reason = collect(value[key], depth + 1, seen);
    if (reason !== REASON.OK) return reason;
  }
  return REASON.OK;
}

function inspectReply(value) {
  const reason = collect(value, 0, new Set());
  if (reason !== REASON.OK) return { ok: false, reason, json: null, bytes: 0 };
  let json;
  try {
    json = JSON.stringify(value);
  } catch (err) {
    return { ok: false, reason: REASON.SERIALIZE_FAILED, json: null, bytes: 0 };
  }
  if (json === undefined) return { ok: false, reason: REASON.UNSUPPORTED_TYPE, json: null, bytes: 0 };
  const bytes = Buffer.byteLength(json, 'utf8');
  if (bytes > MAX_JSON_BYTES) return { ok: false, reason: REASON.TOO_LARGE, json: null, bytes };
  return { ok: true, reason: REASON.OK, json, bytes };
}

function applyReplyGuard(value) {
  const result = inspectReply(value);
  if (!result.ok) return { changed: true, reason: result.reason, json: null };
  return { changed: false, reason: REASON.OK, json: result.json };
}

function describeReason(reason) {
  return describeReasonFrom({
    [REASON.UNSUPPORTED_TYPE]: 'IPC 返回值包含不可序列化类型',
    [REASON.NOT_FINITE]: 'IPC 返回值包含非有限数值',
    [REASON.CIRCULAR]: 'IPC 返回值存在循环引用',
    [REASON.TOO_DEEP]: 'IPC 返回值嵌套层级过深',
    [REASON.TOO_LARGE]: 'IPC 返回值超过体积上限',
    [REASON.SERIALIZE_FAILED]: 'IPC 返回值序列化失败',
  }, reason, 'IPC 返回值结构合法');
}

module.exports = {
  REASON,
  MAX_JSON_BYTES,
  MAX_DEPTH,
  MAX_ITEMS,
  inspectReply,
  applyReplyGuard,
  describeReason,
};
