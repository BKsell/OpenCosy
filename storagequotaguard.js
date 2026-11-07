'use strict';

const REASON = {
  OK: 'ok',
  QUOTA_INVALID: 'storage-quota-invalid',
  QUOTA_TOO_LARGE: 'storage-quota-too-large',
  ORIGIN_INVALID: 'storage-origin-invalid',
  OPAQUE_ORIGIN: 'storage-opaque-origin',
  NEGATIVE_USAGE: 'storage-negative-usage',
  USAGE_EXCEEDS_QUOTA: 'storage-usage-exceeds-quota',
};

const MAX_QUOTA = 512 * 1024 * 1024;
const DEFAULT_QUOTA = 64 * 1024 * 1024;

function evaluateOrigin(value) {
  if (typeof value !== 'string' || value.length === 0) {
    return { ok: false, blocked: true, reason: REASON.ORIGIN_INVALID, origin: '' };
  }
  try {
    const url = new URL(value);
    if (url.protocol === 'about:' || url.protocol === 'data:' || url.protocol === 'javascript:') {
      return { ok: false, blocked: true, reason: REASON.OPAQUE_ORIGIN, origin: value };
    }
    return { ok: true, blocked: false, reason: REASON.OK, origin: url.origin };
  } catch (err) {
    return { ok: false, blocked: true, reason: REASON.ORIGIN_INVALID, origin: value };
  }
}

function evaluateStorageQuota(request) {
  const item = request || {};
  const origin = evaluateOrigin(item.origin);
  if (origin.blocked) return origin;
  let quota = item.quota === undefined || item.quota === null ? DEFAULT_QUOTA : Number(item.quota);
  if (!Number.isFinite(quota) || quota <= 0) {
    return { ok: false, blocked: true, reason: REASON.QUOTA_INVALID, origin: origin.origin, quota: item.quota };
  }
  if (quota > MAX_QUOTA) {
    return { ok: false, blocked: true, reason: REASON.QUOTA_TOO_LARGE, origin: origin.origin, quota };
  }
  const usage = item.usage === undefined || item.usage === null ? 0 : Number(item.usage);
  if (!Number.isFinite(usage) || usage < 0) {
    return { ok: false, blocked: true, reason: REASON.NEGATIVE_USAGE, origin: origin.origin, usage: item.usage };
  }
  if (usage > quota) {
    return { ok: false, blocked: true, reason: REASON.USAGE_EXCEEDS_QUOTA, origin: origin.origin, quota, usage };
  }
  return { ok: true, blocked: false, reason: REASON.OK, origin: origin.origin, quota, usage, remaining: quota - usage };
}

function auditStorageQuotaBatch(list) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateStorageQuota(item);
    if (result.blocked) {
      blocked += 1;
      findings.push({ origin: result.origin, reason: result.reason });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no storage quota risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.origin || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  MAX_QUOTA,
  DEFAULT_QUOTA,
  evaluateOrigin,
  evaluateStorageQuota,
  auditStorageQuotaBatch,
  describeFindings,
};
