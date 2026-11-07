'use strict';

const REASON = {
  OK: 'ok',
  SCHEME_BLOCKED: 'scheme-blocked',
  INVALID: 'invalid-target',
  CREDENTIALS: 'url-credentials',
  NUL_BYTE: 'control-character',
  OBFUSCATED: 'scheme-obfuscation',
  EXTERNAL_HANDOFF: 'external-handoff',
};

const ALLOWED_SCHEMES = new Set(['http:', 'https:', 'mailto:', 'tel:']);

function visible(value) {
  return String(value || '').replace(/[\u0000-\u001f\u007f]/g, '');
}

function evaluate(target) {
  if (typeof target !== 'string' || !target.trim()) return { allowed: false, reason: REASON.INVALID };
  if (/[\u0000-\u001f\u007f]/.test(target)) return { allowed: false, reason: REASON.NUL_BYTE };
  const compact = visible(target).replace(/[\s\u200b-\u200f\ufeff]/g, '');
  const colon = compact.indexOf(':');
  if (colon > 0) {
    const scheme = compact.slice(0, colon).toLowerCase();
    if (!ALLOWED_SCHEMES.has(scheme + ':')) {
      return { allowed: false, reason: REASON.SCHEME_BLOCKED, scheme };
    }
  }
  let url;
  try {
    url = new URL(compact);
  } catch (err) {
    return { allowed: false, reason: REASON.INVALID };
  }
  if (url.username || url.password) return { allowed: false, reason: REASON.CREDENTIALS };
  if (url.protocol === 'mailto:' || url.protocol === 'tel:') {
    return { allowed: true, reason: REASON.OK, external: true };
  }
  return { allowed: true, reason: REASON.OK, url: url.href };
}

function applyGotoLinkGuard(request) {
  const req = request && typeof request === 'object' ? request : {};
  const result = evaluate(req.target);
  const external = result.external === true || result.reason === REASON.SCHEME_BLOCKED;
  return {
    allowed: result.allowed,
    reason: result.reason,
    url: result.url || '',
    requiresHandoff: external && req.confirmExternal !== false,
  };
}

function auditGotoBatch(targets, options) {
  const list = Array.isArray(targets) ? targets : [];
  const findings = [];
  let blocked = 0;
  for (const item of list) {
    const result = evaluate(item);
    if (!result.allowed) blocked += 1;
    if (result.reason !== REASON.OK) findings.push({ target: String(item || '').slice(0, 80), reason: result.reason });
  }
  const limit = Number(options && options.maxFindings) || 10;
  return { blocked, total: list.length, findings: findings.slice(0, limit) };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no goto link risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applyGotoLinkGuard,
  auditGotoBatch,
  describeFindings,
  evaluate,
};
