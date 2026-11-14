'use strict';
const { DEFAULT_TTL_MS, DEFAULT_MAX_PER_ORIGIN, DEFAULT_MAX_ORIGINS, HIGH_RISK_WEIGHT, STATE, normalizeTtl, splitKey, grantKey, recordTime, effectiveDecision } = require('./grantrules_core');
const { describeReasonFrom } = require('./reasontext');

const { safeIntV2 } = require('./modutil_core');
const safeInt = safeIntV2;









function ageDays(record, now) {
  const at = recordTime(record);
  if (at <= 0) return 0;
  const age = now - at;
  if (age <= 0) return 0;
  return Math.floor(age / (24 * 60 * 60 * 1000));
}

function pruneExpired(decisions, options = {}) {
  const now = safeInt(options.now, Date.now());
  const ttl = normalizeTtl(options.ttlMs);
  const removed = [];
  if (!decisions || typeof decisions !== 'object') {
    return { decisions: {}, removed };
  }
  const kept = {};
  for (const [key, record] of Object.entries(decisions)) {
    const state = effectiveDecision(record, now, ttl);
    if (state === STATE.EXPIRED || state === STATE.UNKNOWN) {
      removed.push(key);
      continue;
    }
    kept[key] = record;
  }
  return { decisions: kept, removed };
}

function allowedCount(decisions, origin, now, ttl) {
  let count = 0;
  for (const [key, record] of Object.entries(decisions || {})) {
    const parts = splitKey(key);
    if (!parts || parts.origin !== origin) continue;
    if (effectiveDecision(record, now, ttl) === STATE.ALLOW) count += 1;
  }
  return count;
}

function enforceOriginCap(decisions, origin, options = {}) {
  const now = safeInt(options.now, Date.now());
  const ttl = normalizeTtl(options.ttlMs);
  const cap = safeInt(options.maxPerOrigin, DEFAULT_MAX_PER_ORIGIN);
  if (!decisions || typeof decisions !== 'object' || typeof origin !== 'string') {
    return [];
  }
  const entries = [];
  for (const [key, record] of Object.entries(decisions)) {
    const parts = splitKey(key);
    if (!parts || parts.origin !== origin) continue;
    if (effectiveDecision(record, now, ttl) !== STATE.ALLOW) continue;
    entries.push({ key, permission: parts.permission, at: recordTime(record) });
  }
  if (entries.length <= cap) return [];
  entries.sort((a, b) => {
    const weightDiff = (HIGH_RISK_WEIGHT[a.permission] || 0) - (HIGH_RISK_WEIGHT[b.permission] || 0);
    if (weightDiff !== 0) return weightDiff;
    return a.at - b.at;
  });
  return entries.slice(0, entries.length - cap).map((item) => item.key);
}

function auditGrants(decisions, options = {}) {
  const now = safeInt(options.now, Date.now());
  const ttl = normalizeTtl(options.ttlMs);
  const maxPerOrigin = safeInt(options.maxPerOrigin, DEFAULT_MAX_PER_ORIGIN);
  const result = {
    total: 0,
    allowed: 0,
    denied: 0,
    expired: 0,
    unknown: 0,
    origins: 0,
    overCapOrigins: [],
    riskyOrigins: [],
    oldestDays: 0,
  };
  if (!decisions || typeof decisions !== 'object') return result;
  const perOrigin = new Map();
  for (const [key, record] of Object.entries(decisions)) {
    const parts = splitKey(key);
    if (!parts) continue;
    result.total += 1;
    const state = effectiveDecision(record, now, ttl);
    if (state === STATE.ALLOW) result.allowed += 1;
    else if (state === STATE.DENY) result.denied += 1;
    else if (state === STATE.EXPIRED) result.expired += 1;
    else result.unknown += 1;
    const days = ageDays(record, now);
    if (days > result.oldestDays) result.oldestDays = days;
    let bucket = perOrigin.get(parts.origin);
    if (!bucket) {
      bucket = { allows: 0, weight: 0, permissions: [] };
      perOrigin.set(parts.origin, bucket);
    }
    if (state === STATE.ALLOW) {
      bucket.allows += 1;
      bucket.weight += HIGH_RISK_WEIGHT[parts.permission] || 0;
      if (HIGH_RISK_WEIGHT[parts.permission]) bucket.permissions.push(parts.permission);
    }
  }
  result.origins = perOrigin.size;
  for (const [origin, bucket] of perOrigin) {
    if (bucket.allows > maxPerOrigin) {
      result.overCapOrigins.push({ origin, allows: bucket.allows });
    }
    if (bucket.allows >= 2 && bucket.weight >= 4) {
      result.riskyOrigins.push({
        origin,
        allows: bucket.allows,
        weight: bucket.weight,
        permissions: bucket.permissions.slice().sort(),
      });
    }
  }
  result.overCapOrigins.sort((a, b) => b.allows - a.allows || a.origin.localeCompare(b.origin));
  result.riskyOrigins.sort((a, b) => b.weight - a.weight || a.origin.localeCompare(b.origin));
  if (result.origins > DEFAULT_MAX_ORIGINS) {
    result.capExceeded = true;
  }
  return result;
}

const GRANT_STATE_TEXT = {
  [STATE.ALLOW]: '已允许',
  [STATE.DENY]: '已拒绝',
  [STATE.EXPIRED]: '已过期',
};

function describeGrantState(state) {
  return describeReasonFrom(GRANT_STATE_TEXT, state, '状态未知');
}

function summarizeRisk(report) {
  if (!report || !safeInt(report.total, 0)) return '当前没有已记忆的站点权限决定';
  const parts = [`共 ${report.total} 条决定`, `${report.allowed} 条允许`, `${report.denied} 条拒绝`];
  if (report.expired) parts.push(`${report.expired} 条已过期待清理`);
  if (report.riskyOrigins && report.riskyOrigins.length) {
    parts.push(`${report.riskyOrigins.length} 个站点累计授权过高风险权限`);
  }
  return parts.join('，');
}

module.exports = {
  STATE,
  DEFAULT_TTL_MS,
  DEFAULT_MAX_PER_ORIGIN,
  DEFAULT_MAX_ORIGINS,
  HIGH_RISK_WEIGHT,
  normalizeTtl,
  splitKey,
  grantKey,
  effectiveDecision,
  ageDays,
  pruneExpired,
  allowedCount,
  enforceOriginCap,
  auditGrants,
  describeGrantState,
  summarizeRisk,
};
