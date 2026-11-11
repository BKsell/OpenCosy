"use strict";

const { safeIntV2: safeInt } = require('./modutil');

const DEFAULT_TTL_MS = 30 * 24 * 60 * 60 * 1000;

const DEFAULT_MAX_PER_ORIGIN = 4;

const DEFAULT_MAX_ORIGINS = 400;

const MIN_TTL_MS = 60 * 1000;

const MAX_TTL_MS = 365 * 24 * 60 * 60 * 1000;

const KEY_SEPARATOR = ' ';

const HIGH_RISK_WEIGHT = {
  media: 3,
  'clipboard-read': 3,
  midiSysex: 3,
  geolocation: 2,
  midi: 1,
  notifications: 1,
};

const STATE = {
  ALLOW: 'allow',
  DENY: 'deny',
  EXPIRED: 'expired',
  UNKNOWN: 'unknown',
};

function normalizeTtl(value) {
  const n = safeInt(value, DEFAULT_TTL_MS);
  if (n < MIN_TTL_MS) return MIN_TTL_MS;
  if (n > MAX_TTL_MS) return MAX_TTL_MS;
  return n;
}

function splitKey(key) {
  if (typeof key !== 'string') return null;
  const index = key.indexOf(KEY_SEPARATOR);
  if (index <= 0) return null;
  const origin = key.slice(0, index);
  const permission = key.slice(index + 1);
  if (!origin || !permission) return null;
  return { origin, permission };
}

function grantKey(origin, permission) {
  if (typeof origin !== 'string' || typeof permission !== 'string') return '';
  if (!origin || !permission || origin.includes(KEY_SEPARATOR)) return '';
  return origin + KEY_SEPARATOR + permission;
}

function recordTime(record) {
  if (!record || typeof record !== 'object') return 0;
  return safeInt(record.updatedAt, 0);
}

function effectiveDecision(record, now, ttlMs) {
  if (!record || typeof record !== 'object') return STATE.UNKNOWN;
  if (record.decision !== STATE.ALLOW && record.decision !== STATE.DENY) return STATE.UNKNOWN;
  const at = recordTime(record);
  if (at <= 0) return STATE.UNKNOWN;
  const ttl = normalizeTtl(ttlMs);
  if (now - at >= ttl) return STATE.EXPIRED;
  return record.decision;
}

module.exports = { DEFAULT_TTL_MS, DEFAULT_MAX_PER_ORIGIN, DEFAULT_MAX_ORIGINS, MIN_TTL_MS, MAX_TTL_MS, KEY_SEPARATOR, HIGH_RISK_WEIGHT, STATE, normalizeTtl, splitKey, grantKey, recordTime, effectiveDecision };
