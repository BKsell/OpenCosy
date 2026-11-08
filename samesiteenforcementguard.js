'use strict';

const REASON = {
  OK: 'ok',
  INVALID: 'samesite-request-invalid',
  CROSS_SITE_STRICT: 'samesite-cross-site-strict',
  CROSS_SITE_LAX_UNSAFE_METHOD: 'samesite-lax-unsafe-method',
  MISSING_SAMESITE: 'samesite-missing',
  DOWNGRADE: 'samesite-scheme-downgrade',
};

const SAFE_METHODS = new Set(['get', 'head', 'options', 'trace']);

function siteOf(url) {
  try {
    const parsed = new URL(String(url || ''));
    return parsed.hostname.toLowerCase();
  } catch (err) {
    return '';
  }
}

function evaluateSameSiteRequest(request) {
  const req = request || {};
  if (typeof req.url !== 'string' || typeof req.initiator !== 'string') {
    return { ok: false, blocked: true, reason: REASON.INVALID, url: String(req.url || '') };
  }
  const target = siteOf(req.url);
  const origin = siteOf(req.initiator);
  if (target === '' || origin === '') {
    return { ok: false, blocked: true, reason: REASON.INVALID, url: String(req.url || '') };
  }
  if (req.url.startsWith('http:') && req.initiator.startsWith('https:')) {
    return { ok: false, blocked: true, reason: REASON.DOWNGRADE, target, origin };
  }
  const crossSite = target !== origin;
  if (!crossSite) return { ok: true, blocked: false, reason: REASON.OK, target, origin };
  const mode = String(req.cookieSameSite || 'unspecified').toLowerCase();
  const method = String(req.method || 'GET').toLowerCase();
  if (mode === 'strict') {
    return { ok: false, blocked: true, reason: REASON.CROSS_SITE_STRICT, target, origin };
  }
  if (mode === 'lax' && !SAFE_METHODS.has(method)) {
    return { ok: false, blocked: true, reason: REASON.CROSS_SITE_LAX_UNSAFE_METHOD, target, origin, method };
  }
  if (mode === 'unspecified') {
    return { ok: false, blocked: true, reason: REASON.MISSING_SAMESITE, target, origin, method };
  }
  return { ok: true, blocked: false, reason: REASON.OK, target, origin, sameSite: mode };
}

function auditSameSiteBatch(list) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateSameSiteRequest(item);
    if (result.blocked) {
      blocked += 1;
      findings.push({ reason: result.reason, target: result.target, origin: result.origin });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no same-site risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.target || '') + '<' + String(f.origin || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  SAFE_METHODS,
  evaluateSameSiteRequest,
  auditSameSiteBatch,
  describeFindings,
};
