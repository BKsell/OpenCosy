'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'cookie-header-empty',
  TOO_LONG: 'cookie-header-too-long',
  CONTROL_CHARS: 'cookie-header-control-chars',
  NO_SECURE: 'cookie-missing-secure',
  NO_HTTPONLY: 'cookie-missing-httponly',
  SAMESITE_NONE_INSECURE: 'cookie-samesite-none-insecure',
  SAMESITE_INVALID: 'cookie-samesite-invalid',
  PREFIX_MISMATCH: 'cookie-prefix-mismatch',
  DOMAIN_TOO_BROAD: 'cookie-domain-too-broad',
  EXPIRY_CONFLICT: 'cookie-expiry-conflict',
  VALUE_INVALID: 'cookie-value-invalid',
};

const MAX_HEADER = 4096;
const MAX_VALUE = 4096;

function evaluateSetCookie(header, options) {
  const opts = options || {};
  if (typeof header !== 'string' || header.trim() === '') {
    return { ok: false, blocked: true, reason: REASON.EMPTY, name: '' };
  }
  if (header.length > MAX_HEADER) {
    return { ok: false, blocked: true, reason: REASON.TOO_LONG, name: '' };
  }
  if (/[\u0000-\u001f\u007f]/.test(header)) {
    return { ok: false, blocked: true, reason: REASON.CONTROL_CHARS, name: '' };
  }
  const segments = header.split(';');
  const pair = segments[0] || '';
  const eq = pair.indexOf('=');
  if (eq <= 0) return { ok: false, blocked: true, reason: REASON.VALUE_INVALID, name: pair.trim() };
  const name = pair.slice(0, eq).trim();
  const value = pair.slice(eq + 1).trim();
  if (name === '' || value.length > MAX_VALUE) {
    return { ok: false, blocked: true, reason: REASON.VALUE_INVALID, name };
  }
  const attrs = {};
  for (const segment of segments.slice(1)) {
    const item = segment.trim();
    if (item === '') continue;
    const pos = item.indexOf('=');
    const key = (pos < 0 ? item : item.slice(0, pos)).trim().toLowerCase();
    const val = pos < 0 ? '' : item.slice(pos + 1).trim();
    attrs[key] = val;
  }
  if (name.startsWith('__Secure-') && attrs.secure === undefined) {
    return { ok: false, blocked: true, reason: REASON.PREFIX_MISMATCH, name };
  }
  if (name.startsWith('__Host-')) {
    if (attrs.secure === undefined || attrs.domain !== undefined || (attrs.path || '') !== '/') {
      return { ok: false, blocked: true, reason: REASON.PREFIX_MISMATCH, name };
    }
  }
  if (attrs.secure === undefined) {
    return { ok: false, blocked: true, reason: REASON.NO_SECURE, name };
  }
  if (opts.httpOnlyRequired !== false && attrs.httponly === undefined) {
    return { ok: false, blocked: true, reason: REASON.NO_HTTPONLY, name };
  }
  if (attrs.samesite !== undefined) {
    const mode = String(attrs.samesite).toLowerCase();
    if (mode !== 'strict' && mode !== 'lax' && mode !== 'none') {
      return { ok: false, blocked: true, reason: REASON.SAMESITE_INVALID, name, sameSite: mode };
    }
    if (mode === 'none' && attrs.secure === undefined) {
      return { ok: false, blocked: true, reason: REASON.SAMESITE_NONE_INSECURE, name };
    }
  }
  if (attrs['max-age'] !== undefined && attrs.expires !== undefined) {
    return { ok: false, blocked: true, reason: REASON.EXPIRY_CONFLICT, name };
  }
  if (attrs.domain !== undefined) {
    const domain = attrs.domain.replace(/^\./, '').toLowerCase();
    if (domain === '' || domain === 'localhost' || domain.split('.').length < 2) {
      return { ok: false, blocked: true, reason: REASON.DOMAIN_TOO_BROAD, name, domain };
    }
  }
  return { ok: true, blocked: false, reason: REASON.OK, name, secure: true, attributes: attrs };
}

function auditSetCookieHeaders(headers, options) {
  const items = Array.isArray(headers) ? headers : [];
  const findings = [];
  let blocked = 0;
  for (const header of items) {
    const result = evaluateSetCookie(header, options);
    if (result.blocked) {
      blocked += 1;
      findings.push({ reason: result.reason, name: result.name });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no set-cookie risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.name || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  MAX_HEADER,
  evaluateSetCookie,
  auditSetCookieHeaders,
  describeFindings,
};
