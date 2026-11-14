'use strict';

const { safeInt } = require('./modutil_core');

const DEFAULT_LIMIT_BYTES = 8 * 1024 * 1024 * 1024;
const MIN_LIMIT_BYTES = 16 * 1024 * 1024;
const MAX_LIMIT_BYTES = 64 * 1024 * 1024 * 1024;

const REASON = {
  OK: 'ok',
  UNLIMITED: 'unlimited',
  DECLARED_TOO_LARGE: 'declared-too-large',
  GROWING_TOO_LARGE: 'growing-too-large',
};

const ACTION = { ALLOW: 'allow', CANCEL: 'cancel' };

function normalizeLimit(value) {
  if (value === 0) return 0;
  const n = safeInt(value);
  if (n == null || n <= 0) return DEFAULT_LIMIT_BYTES;
  if (n < MIN_LIMIT_BYTES) return MIN_LIMIT_BYTES;
  if (n > MAX_LIMIT_BYTES) return MAX_LIMIT_BYTES;
  return n;
}

function decideDeclared(totalBytes, limit) {
  const cap = normalizeLimit(limit);
  const total = safeInt(totalBytes);
  if (cap === 0) return { action: ACTION.ALLOW, reason: REASON.UNLIMITED, totalBytes: total, limitBytes: cap };
  if (total == null || total <= 0) {
    return { action: ACTION.ALLOW, reason: REASON.OK, totalBytes: total, limitBytes: cap };
  }
  if (total > cap) {
    return { action: ACTION.CANCEL, reason: REASON.DECLARED_TOO_LARGE, totalBytes: total, limitBytes: cap };
  }
  return { action: ACTION.ALLOW, reason: REASON.OK, totalBytes: total, limitBytes: cap };
}

function decideProgress(receivedBytes, limit) {
  const cap = normalizeLimit(limit);
  const received = safeInt(receivedBytes);
  if (cap === 0) return { action: ACTION.ALLOW, reason: REASON.UNLIMITED, receivedBytes: received, limitBytes: cap };
  if (received != null && received > cap) {
    return { action: ACTION.CANCEL, reason: REASON.GROWING_TOO_LARGE, receivedBytes: received, limitBytes: cap };
  }
  return { action: ACTION.ALLOW, reason: REASON.OK, receivedBytes: received, limitBytes: cap };
}

function describe(decision) {
  if (!decision || decision.action === ACTION.ALLOW) {
    return decision && decision.reason === REASON.UNLIMITED ? '下载体积上限已关闭' : '下载体积在上限内';
  }
  const limit = formatBytes(decision.limitBytes);
  if (decision.reason === REASON.DECLARED_TOO_LARGE) {
    return `声明体积 ${formatBytes(decision.totalBytes)} 超过上限 ${limit}`;
  }
  return `已接收 ${formatBytes(decision.receivedBytes)} 超过上限 ${limit}`;
}

function formatBytes(bytes) {
  const n = safeInt(bytes);
  if (n == null || n <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = n;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const shown = value >= 100 || unit === 0 ? Math.round(value) : Math.round(value * 10) / 10;
  return `${shown} ${units[unit]}`;
}

module.exports = {
  DEFAULT_LIMIT_BYTES,
  MIN_LIMIT_BYTES,
  MAX_LIMIT_BYTES,
  REASON,
  ACTION,
  normalizeLimit,
  decideDeclared,
  decideProgress,
  describe,
  formatBytes,
};
