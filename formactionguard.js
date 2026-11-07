'use strict';

const REASON = {
  OK: 'ok',
  INVALID: 'invalid-action',
  INSECURE: 'insecure-action',
  CROSS_ORIGIN: 'cross-origin-action',
  CREDENTIALS: 'action-credentials',
  JAVASCRIPT: 'javascript-action',
  FILES_EXFIL: 'file-input-exfiltration',
};

function parse(value) {
  if (typeof value !== 'string' || !value) return null;
  try {
    return new URL(value);
  } catch (err) {
    return null;
  }
}

function sameOrigin(a, b) {
  return a.protocol === b.protocol && a.host === b.host;
}

function evaluate(request) {
  const req = request && typeof request === 'object' ? request : {};
  const action = String(req.action || '').trim();
  if (!action) return { action: 'allow', reason: REASON.OK, url: req.pageUrl || '' };
  if (/^javascript:/i.test(action.replace(/\s/g, ''))) {
    return { action: 'block', reason: REASON.JAVASCRIPT, url: '' };
  }
  const page = parse(req.pageUrl);
  const target = parse(action);
  if (!target) return { action: 'block', reason: REASON.INVALID, url: '' };
  if (target.username || target.password) return { action: 'block', reason: REASON.CREDENTIALS, url: '' };
  if (target.protocol === 'http:' && page && page.protocol === 'https:') {
    return { action: 'block', reason: REASON.INSECURE, url: action };
  }
  if (target.protocol !== 'https:' && target.protocol !== 'http:') {
    return { action: 'block', reason: REASON.INVALID, url: action };
  }
  if (page && !sameOrigin(page, target)) {
    if (req.hasFileInput) return { action: 'block', reason: REASON.FILES_EXFIL, url: action };
    return { action: 'rewrite', reason: REASON.CROSS_ORIGIN, url: action };
  }
  return { action: 'allow', reason: REASON.OK, url: action };
}

function applyFormActionGuard(request) {
  const req = request && typeof request === 'object' ? request : {};
  const result = evaluate(req);
  return {
    action: result.action,
    blocked: result.action === 'block',
    url: result.url,
    reason: result.reason,
    requireConfirm: result.action === 'rewrite',
  };
}

function auditFormBatch(forms, options) {
  const list = Array.isArray(forms) ? forms : [];
  const findings = [];
  let blocked = 0;
  let confirm = 0;
  for (const item of list) {
    const result = evaluate(item);
    if (result.action === 'block') blocked += 1;
    if (result.action === 'rewrite') confirm += 1;
    if (result.reason !== REASON.OK) findings.push({ action: item && item.action, reason: result.reason });
  }
  const limit = Number(options && options.maxFindings) || 10;
  return { blocked, confirm, total: list.length, findings: findings.slice(0, limit) };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no form action risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applyFormActionGuard,
  auditFormBatch,
  describeFindings,
};
