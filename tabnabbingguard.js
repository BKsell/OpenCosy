'use strict';

const REASON = {
  OK: 'ok',
  OPENER_SEVERED: 'opener-severed',
  REL_ADDED: 'rel-added',
  UNTRUSTED_TARGET: 'untrusted-target',
  INVALID: 'invalid-target',
};

const DANGEROUS_TARGETS = new Set(['_blank', '_new', 'blank']);

function parse(value) {
  if (typeof value !== 'string' || !value) return null;
  try {
    return new URL(value);
  } catch (err) {
    return null;
  }
}

function siteKey(host) {
  const parts = String(host || '').toLowerCase().split('.');
  if (parts.length < 2) return parts.join('.');
  return parts.slice(-2).join('.');
}

function tokenList(rel) {
  if (typeof rel !== 'string') return [];
  return rel
    .toLowerCase()
    .split(/\s+/)
    .map((t) => t.trim())
    .filter(Boolean);
}

function evaluate(request) {
  const req = request && typeof request === 'object' ? request : {};
  const target = String(req.target || '').trim().toLowerCase();
  if (!target) return { action: 'allow', reason: REASON.OK, rel: tokenList(req.rel) };
  if (!DANGEROUS_TARGETS.has(target)) {
    if (target.startsWith('_')) return { action: 'block', reason: REASON.UNTRUSTED_TARGET, rel: [] };
    return { action: 'allow', reason: REASON.OK, rel: tokenList(req.rel) };
  }
  const current = parse(req.currentUrl);
  const destination = parse(req.url);
  const crossOrigin = current && destination ? siteKey(current.hostname) !== siteKey(destination.hostname) : true;
  const rel = tokenList(req.rel);
  if (!crossOrigin) return { action: 'allow', reason: REASON.OK, rel };
  const missing = [];
  if (!rel.includes('noopener')) missing.push('noopener');
  if (!rel.includes('noreferrer')) missing.push('noreferrer');
  if (missing.length === 0) return { action: 'allow', reason: REASON.OK, rel };
  return { action: 'rewrite', reason: missing.includes('noopener') ? REASON.OPENER_SEVERED : REASON.REL_ADDED, rel: rel.concat(missing) };
}

function applyTabnabbingGuard(request) {
  const result = evaluate(request);
  const rel = Array.from(new Set(result.rel)).sort();
  return {
    action: result.action,
    blocked: result.action === 'block',
    rel: rel.join(' '),
    reason: result.reason,
  };
}

function auditLinkBatch(links, options) {
  const list = Array.isArray(links) ? links : [];
  const findings = [];
  let rewritten = 0;
  let blocked = 0;
  for (const item of list) {
    const result = evaluate(item);
    if (result.action === 'rewrite') rewritten += 1;
    if (result.action === 'block') blocked += 1;
    if (result.reason !== REASON.OK) findings.push({ url: item && item.url, reason: result.reason });
  }
  const limit = Number(options && options.maxFindings) || 10;
  return { rewritten, blocked, total: list.length, findings: findings.slice(0, limit) };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no tabnabbing risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applyTabnabbingGuard,
  auditLinkBatch,
  describeFindings,
};
