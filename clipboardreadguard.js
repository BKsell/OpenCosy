'use strict';

const REASON = {
  OK: 'ok',
  ORIGIN_MISSING: 'origin-missing',
  INSECURE_ORIGIN: 'insecure-origin',
  NO_GESTURE: 'no-user-gesture',
  TOO_LARGE: 'clipboard-too-large',
  SECRET_CONTENT: 'secret-content',
  UNKNOWN_TYPE: 'unknown-clipboard-type',
};

const SENSITIVE_PATTERNS = [
  /ghp_[A-Za-z0-9]{20,}/,
  /github_pat_[A-Za-z0-9_]{20,}/,
  /sk-[A-Za-z0-9]{16,}/,
  /-----BEGIN [A-Z ]+PRIVATE KEY-----/,
  /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/,
];

function parse(value) {
  if (typeof value !== 'string' || !value) return null;
  try {
    return new URL(value);
  } catch (err) {
    return null;
  }
}

function hasSecret(text) {
  return SENSITIVE_PATTERNS.some((re) => re.test(String(text || '')));
}

function evaluate(request) {
  const req = request && typeof request === 'object' ? request : {};
  const origin = parse(req.origin);
  if (!origin) return { allowed: false, reason: REASON.ORIGIN_MISSING };
  if (origin.protocol !== 'https:' && req.allowInsecure !== true) {
    return { allowed: false, reason: REASON.INSECURE_ORIGIN };
  }
  if (req.userGesture !== true) return { allowed: false, reason: REASON.NO_GESTURE };
  const size = Number(req.size) || String(req.text || '').length;
  if (size > (Number(req.maxSize) || 32768)) return { allowed: false, reason: REASON.TOO_LARGE };
  if (Array.isArray(req.types) && req.types.some((t) => !['text/plain', 'text/html', 'image/png'].includes(String(t)))) {
    return { allowed: false, reason: REASON.UNKNOWN_TYPE };
  }
  if (hasSecret(req.text) && req.allowSecret !== true) {
    return { allowed: false, reason: REASON.SECRET_CONTENT };
  }
  return { allowed: true, reason: REASON.OK };
}

function applyClipboardReadGuard(request) {
  const req = request && typeof request === 'object' ? request : {};
  const result = evaluate(req);
  const text = result.allowed ? String(req.text || '') : '';
  return {
    allowed: result.allowed,
    reason: result.reason,
    text: result.allowed ? text.slice(0, Number(req.maxSize) || 32768) : '',
    redacted: result.reason === REASON.SECRET_CONTENT,
  };
}

function auditClipboardBatch(requests, options) {
  const list = Array.isArray(requests) ? requests : [];
  const findings = [];
  let denied = 0;
  for (const item of list) {
    const result = evaluate(item);
    if (!result.allowed) denied += 1;
    if (result.reason !== REASON.OK) findings.push({ origin: item && item.origin, reason: result.reason });
  }
  const limit = Number(options && options.maxFindings) || 10;
  return { denied, total: list.length, findings: findings.slice(0, limit) };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no clipboard read risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applyClipboardReadGuard,
  auditClipboardBatch,
  describeFindings,
};
