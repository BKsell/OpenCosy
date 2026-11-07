'use strict';

const REASON = {
  OK: 'ok',
  ORIGIN_MISSING: 'origin-missing',
  INSECURE_ORIGIN: 'insecure-origin',
  MUTED_ORIGIN: 'muted-origin',
  SENSITIVE_BODY: 'sensitive-body',
  RATE_LIMITED: 'rate-limited',
  TAG_ABUSE: 'tag-abuse',
};

function parse(value) {
  if (typeof value !== 'string' || !value) return null;
  try {
    return new URL(value);
  } catch (err) {
    return null;
  }
}

function stripSensitive(text) {
  return String(text || '')
    .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '<redacted>')
    .replace(/\b\d{6,}\b/g, '<redacted>');
}

function evaluate(request) {
  const req = request && typeof request === 'object' ? request : {};
  const origin = parse(req.origin);
  if (!origin) return { allowed: false, reason: REASON.ORIGIN_MISSING };
  if (origin.protocol !== 'https:' && req.allowInsecure !== true) {
    return { allowed: false, reason: REASON.INSECURE_ORIGIN };
  }
  if (Array.isArray(req.mutedOrigins) && req.mutedOrigins.includes(origin.hostname)) {
    return { allowed: false, reason: REASON.MUTED_ORIGIN };
  }
  if (Number(req.pendingCount) > 5) return { allowed: false, reason: REASON.RATE_LIMITED };
  if (typeof req.tag === 'string' && req.tag.includes('-') && req.tag.length > 32) {
    return { allowed: false, reason: REASON.TAG_ABUSE };
  }
  if (/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/.test(String(req.body || ''))) {
    return { allowed: true, reason: REASON.SENSITIVE_BODY, sanitized: true };
  }
  return { allowed: true, reason: REASON.OK };
}

function applyNotificationPolicyGuard(request) {
  const req = request && typeof request === 'object' ? request : {};
  const result = evaluate(req);
  const sanitized = result.reason === REASON.SENSITIVE_BODY;
  return {
    allowed: result.allowed,
    reason: result.reason,
    body: result.allowed ? stripSensitive(req.body) : '',
    title: result.allowed ? stripSensitive(req.title) : '',
    silent: Boolean(req.silent) || sanitized,
  };
}

function auditNotificationBatch(requests, options) {
  const list = Array.isArray(requests) ? requests : [];
  const findings = [];
  let blocked = 0;
  let sanitized = 0;
  for (const item of list) {
    const result = evaluate(item);
    if (!result.allowed) blocked += 1;
    if (result.reason === REASON.SENSITIVE_BODY) sanitized += 1;
    if (result.reason !== REASON.OK) findings.push({ origin: item && item.origin, reason: result.reason });
  }
  const limit = Number(options && options.maxFindings) || 10;
  return { blocked, sanitized, total: list.length, findings: findings.slice(0, limit) };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no notification risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applyNotificationPolicyGuard,
  auditNotificationBatch,
  describeFindings,
};
