'use strict';

const REASON = {
  OK: 'ok',
  THIRD_PARTY_UNPARTITIONED: 'cookie-third-party-unpartitioned',
  INSECURE_COOKIE: 'cookie-requires-secure',
  SAMESITE_NONE: 'cookie-samesite-none',
  WILDCARD_DOMAIN: 'cookie-wildcard-domain',
  OVERLY_BROAD_DOMAIN: 'cookie-overly-broad-domain',
  CREDENTIAL_COOKIE_HTTPONLY: 'cookie-credential-missing-httponly',
};

const CREDENTIAL_HINTS = ['session', 'auth', 'token', 'sid', 'login'];
const PUBLIC_SUFFIXES = new Set(['com', 'org', 'net', 'io', 'cn', 'co', 'uk', 'gov', 'edu']);

function isThirdParty(initiatorSite, targetSite) {
  const left = String(initiatorSite || '').toLowerCase();
  const right = String(targetSite || '').toLowerCase();
  if (!left || !right) return false;
  return left !== right;
}

function registrableDomain(host) {
  const parts = String(host || '').toLowerCase().split('.').filter(Boolean);
  if (parts.length <= 2) return parts.join('.');
  const last = parts[parts.length - 1];
  const second = parts[parts.length - 2];
  if (PUBLIC_SUFFIXES.has(second) && last.length === 2) return parts.slice(-3).join('.');
  return parts.slice(-2).join('.');
}

function evaluateCookie(cookie, context) {
  const c = cookie || {};
  const ctx = context || {};
  const name = String(c.name || '').toLowerCase();
  const secure = c.secure === true;
  const httpOnly = c.httpOnly === true;
  const sameSite = String(c.sameSite || '').toLowerCase();
  if (c.domain && String(c.domain).startsWith('*')) {
    return { ok: false, blocked: true, reason: REASON.WILDCARD_DOMAIN, name };
  }
  if (c.domain && c.domain.includes('.') && registrableDomain(String(c.domain).replace(/^\./, '')) !== String(c.domain).replace(/^\./, '').toLowerCase()) {
    return { ok: false, blocked: true, reason: REASON.OVERLY_BROAD_DOMAIN, name, domain: c.domain };
  }
  if (!secure && ctx.secureContext !== false) {
    return { ok: false, blocked: true, reason: REASON.INSECURE_COOKIE, name };
  }
  if (sameSite === 'none' && !secure) {
    return { ok: false, blocked: true, reason: REASON.SAMESITE_NONE, name };
  }
  if (CREDENTIAL_HINTS.some((hint) => name.includes(hint)) && !httpOnly) {
    return { ok: false, blocked: true, reason: REASON.CREDENTIAL_COOKIE_HTTPONLY, name };
  }
  if (isThirdParty(ctx.initiatorSite, ctx.targetSite) && c.partitioned !== true) {
    return { ok: false, blocked: true, reason: REASON.THIRD_PARTY_UNPARTITIONED, name, domain: c.domain || '' };
  }
  return { ok: true, blocked: false, reason: REASON.OK, name, partitioned: c.partitioned === true };
}

function auditCookieBatch(list, context) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateCookie(item, context);
    if (result.blocked) {
      blocked += 1;
      findings.push({ name: result.name, reason: result.reason });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no cookie partition risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.name || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  evaluateCookie,
  auditCookieBatch,
  describeFindings,
  registrableDomain,
  isThirdParty,
};
