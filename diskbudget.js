"use strict";

const MIN_FREE_BYTES = 512 * 1024 * 1024;

const LOW_FREE_BYTES = 256 * 1024 * 1024;

const RESERVE_RATIO = 0.15;

const MAX_RESERVE_BYTES = 4 * 1024 * 1024 * 1024;

const MAX_NAME_BYTES = 240;

const ACTION = Object.freeze({
  ALLOW: 'allow',
  WARN: 'warn',
  BLOCK: 'block',
});

const PROGRESS = Object.freeze({
  CONTINUE: 'continue',
  PAUSE: 'pause',
});

const REASON = Object.freeze({
  OK: 'ok',
  INVALID: 'invalid',
  INSUFFICIENT: 'insufficient',
  LOW_FREE: 'low-free',
  UNKNOWN_SIZE: 'unknown-size',
  EXISTING_FILE: 'existing-file',
  PAUSED_LOW_FREE: 'paused-low-free',
  RECOVERED: 'recovered',
  NOT_TRACKED: 'not-tracked',
});

function safeBytes(value) {
  const num = Number(value);
  if (!Number.isFinite(num) || num < 0) return 0;
  if (num > Number.MAX_SAFE_INTEGER) return Number.MAX_SAFE_INTEGER;
  return Math.floor(num);
}

function requiredReserve(totalBytes) {
  const total = safeBytes(totalBytes);
  const proportional = Math.min(MAX_RESERVE_BYTES, Math.ceil(total * RESERVE_RATIO));
  return Math.max(MIN_FREE_BYTES, proportional);
}

function requiredFreeBytes(totalBytes) {
  return safeBytes(totalBytes) + requiredReserve(totalBytes);
}

module.exports = { MIN_FREE_BYTES, LOW_FREE_BYTES, RESERVE_RATIO, MAX_RESERVE_BYTES, MAX_NAME_BYTES, ACTION, PROGRESS, REASON, safeBytes, requiredReserve, requiredFreeBytes };
