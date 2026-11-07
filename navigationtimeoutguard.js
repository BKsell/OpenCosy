'use strict';

const REASON = {
  OK: 'ok',
  TOO_LONG: 'timeout-too-long',
  TOO_SHORT: 'timeout-too-short',
  INVALID: 'invalid-timeout',
  RETRY_EXHAUSTED: 'retry-exhausted',
  SLOW_HOST: 'slow-host-throttled',
};

const DEFAULT = 30000;
const MIN = 3000;
const MAX = 120000;

function normalizeTimeout(value, options) {
  const opts = options && typeof options === 'object' ? options : {};
  const min = Number(opts.min) || MIN;
  const max = Number(opts.max) || MAX;
  const num = Number(value);
  if (!Number.isFinite(num) || num <= 0) return { timeout: DEFAULT, reason: REASON.INVALID, clamped: true };
  if (num < min) return { timeout: min, reason: REASON.TOO_SHORT, clamped: true };
  if (num > max) return { timeout: max, reason: REASON.TOO_LONG, clamped: true };
  return { timeout: Math.round(num), reason: REASON.OK, clamped: false };
}

function evaluate(request) {
  const req = request && typeof request === 'object' ? request : {};
  const base = normalizeTimeout(req.timeout, req.options);
  const retries = Number(req.retries);
  if (Number.isFinite(retries) && retries < 0) return { blocked: true, reason: REASON.INVALID, timeout: base.timeout };
  if (Number.isFinite(retries) && retries > 3) return { blocked: true, reason: REASON.RETRY_EXHAUSTED, timeout: base.timeout };
  if (Array.isArray(req.slowHosts) && req.slowHosts.includes(req.host)) {
    return { blocked: false, reason: REASON.SLOW_HOST, timeout: Math.min(base.timeout, 15000), backoff: true };
  }
  return { blocked: false, reason: base.reason, timeout: base.timeout, backoff: false };
}

function applyNavigationTimeoutGuard(request) {
  const req = request && typeof request === 'object' ? request : {};
  const result = evaluate(req);
  return {
    timeout: result.timeout,
    blocked: result.blocked,
    reason: result.reason,
    backoff: Boolean(result.backoff),
    retriesAllowed: Math.min(Math.max(Number(req.retries) || 0, 0), 3),
  };
}

function auditTimeoutBatch(requests, options) {
  const list = Array.isArray(requests) ? requests : [];
  const findings = [];
  let clamped = 0;
  for (const item of list) {
    const result = evaluate(item);
    if (result.reason !== REASON.OK) clamped += 1;
    if (result.reason !== REASON.OK) findings.push({ host: item && item.host, reason: result.reason });
  }
  const limit = Number(options && options.maxFindings) || 10;
  return { clamped, total: list.length, findings: findings.slice(0, limit) };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no timeout risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applyNavigationTimeoutGuard,
  auditTimeoutBatch,
  describeFindings,
  normalizeTimeout,
};
