'use strict';

const REASON = {
  OK: 'ok',
  INVALID: 'invalid-url',
  CREDENTIAL_IN_FRAME: 'credential-form-in-frame',
  OPAQUE_ORIGIN: 'opaque-origin-frame',
  SANDBOX_ESCAPE: 'sandbox-escape-tokens',
  CROSS_SITE_FRAME: 'cross-site-credential-frame',
  PASSWORD_MANAGER: 'password-manager-disabled',
};

const DANGEROUS_SANDBOX = new Set([
  'allow-same-origin',
  'allow-top-navigation',
  'allow-top-navigation-by-user-activation',
  'allow-popups-to-escape-sandbox',
  'allow-modals',
]);

const CREDENTIAL_FIELDS = new Set(['password', 'username', 'email', 'new-password', 'current-password', 'one-time-code']);

function splitSandbox(value) {
  if (typeof value !== 'string') return [];
  return value
    .split(/\s+/)
    .map((t) => t.trim().toLowerCase())
    .filter(Boolean);
}

function parseUrl(value) {
  if (typeof value !== 'string' || !value) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    return url;
  } catch (err) {
    return null;
  }
}

function siteKey(host) {
  const parts = String(host || '').toLowerCase().split('.');
  if (parts.length < 2) return parts.join('.');
  return parts.slice(-2).join('.');
}

function evaluate(request) {
  const req = request && typeof request === 'object' ? request : {};
  const frame = parseUrl(req.frameUrl);
  const top = parseUrl(req.topUrl);
  if (!frame) return { blocked: true, reason: REASON.INVALID, detail: 'frame url invalid' };
  const tokens = splitSandbox(req.sandbox);
  const opaque = tokens.includes('allow-same-origin') === false;
  const fieldTypes = Array.isArray(req.fieldTypes) ? req.fieldTypes.map((t) => String(t).toLowerCase()) : [];
  const hasCredentialField = fieldTypes.some((t) => CREDENTIAL_FIELDS.has(t));
  const dangerous = tokens.filter((t) => DANGEROUS_SANDBOX.has(t));
  if (req.credentialForm && opaque) {
    return { blocked: true, reason: REASON.OPAQUE_ORIGIN, detail: 'credential form in sandboxed opaque frame' };
  }
  if (hasCredentialField && top && siteKey(top.hostname) !== siteKey(frame.hostname)) {
    return { blocked: true, reason: REASON.CROSS_SITE_FRAME, detail: frame.hostname };
  }
  if (req.credentialForm && dangerous.length > 0) {
    return { blocked: true, reason: REASON.SANDBOX_ESCAPE, detail: dangerous.join(',') };
  }
  if (req.credentialForm && req.suppressPasswordManager) {
    return { blocked: false, reason: REASON.PASSWORD_MANAGER, detail: 'autocomplete disabled' };
  }
  return { blocked: false, reason: REASON.OK, detail: '' };
}

function applyIframeCredentialGuard(request) {
  const result = evaluate(request);
  const attributes = {};
  if (result.blocked) attributes.sandbox = '';
  return {
    blocked: result.blocked,
    reason: result.reason,
    detail: result.detail,
    attributes,
  };
}

function normalizeSandbox(value) {
  const tokens = splitSandbox(value);
  const seen = new Set();
  const out = [];
  for (const token of tokens) {
    if (seen.has(token)) continue;
    seen.add(token);
    out.push(token);
  }
  if (seen.has('allow-scripts') && seen.has('allow-same-origin')) {
    return { value: out.join(' '), escapes: true, tokens: out };
  }
  return { value: out.join(' '), escapes: false, tokens: out };
}

function auditEmbedBatch(frames, options) {
  const list = Array.isArray(frames) ? frames : [];
  const findings = [];
  let blocked = 0;
  for (const item of list) {
    const result = evaluate(item);
    if (result.blocked) blocked += 1;
    if (result.reason !== REASON.OK) findings.push({ frameUrl: item && item.frameUrl, reason: result.reason, detail: result.detail });
  }
  const limit = Number(options && options.maxFindings) || 8;
  return { blocked, findings: findings.slice(0, limit), total: list.length };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no iframe credential risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applyIframeCredentialGuard,
  auditEmbedBatch,
  describeFindings,
  normalizeSandbox,
};
