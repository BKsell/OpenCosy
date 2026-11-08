'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'request-header-empty',
  TOO_LONG: 'request-header-too-long',
  CONTROL_CHARS: 'request-header-control-chars',
  CREDENTIAL_CROSS_ORIGIN: 'request-header-credential-leak',
  PROXY_CREDENTIAL: 'request-header-proxy-credential',
  SPOOFED_FORWARD: 'request-header-spoofed-forward',
  HOST_OVERRIDE: 'request-header-host-override',
};

const MAX_HEADER = 8192;
const SENSITIVE = new Set(['authorization', 'cookie', 'proxy-authorization', 'x-api-key', 'x-auth-token']);
const FORWARD_HEADERS = new Set(['x-forwarded-for', 'x-forwarded-host', 'x-real-ip', 'forwarded']);

function evaluateOutgoingHeaders(headers, options) {
  const opts = options || {};
  const list = Array.isArray(headers) ? headers : Object.keys(headers || {}).map((key) => [key, headers[key]]);
  if (list.length === 0) return { ok: false, blocked: true, reason: REASON.EMPTY, name: '' };
  const sameOrigin = opts.sameOrigin === true;
  for (const entry of list) {
    const pair = Array.isArray(entry) ? entry : [entry && entry.name, entry && entry.value];
    const name = String(pair[0] || '').trim();
    const value = String(pair[1] === undefined || pair[1] === null ? '' : pair[1]);
    const lower = name.toLowerCase();
    if (lower === '') return { ok: false, blocked: true, reason: REASON.EMPTY, name };
    if (name.length + value.length > MAX_HEADER) {
      return { ok: false, blocked: true, reason: REASON.TOO_LONG, name };
    }
    if (/[\u0000-\u001f\u007f]/.test(name + value)) {
      return { ok: false, blocked: true, reason: REASON.CONTROL_CHARS, name };
    }
    if (lower === 'host' && opts.allowHostOverride !== true) {
      return { ok: false, blocked: true, reason: REASON.HOST_OVERRIDE, name };
    }
    if (lower === 'proxy-authorization') {
      return { ok: false, blocked: true, reason: REASON.PROXY_CREDENTIAL, name };
    }
    if (FORWARD_HEADERS.has(lower) && opts.allowForwarding !== true) {
      return { ok: false, blocked: true, reason: REASON.SPOOFED_FORWARD, name };
    }
    if (SENSITIVE.has(lower) && !sameOrigin) {
      return { ok: false, blocked: true, reason: REASON.CREDENTIAL_CROSS_ORIGIN, name };
    }
  }
  return { ok: true, blocked: false, reason: REASON.OK, count: list.length };
}

function auditHeaderBatch(list, options) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateOutgoingHeaders(item && item.headers ? item.headers : item, options);
    if (result.blocked) {
      blocked += 1;
      findings.push({ name: result.name, reason: result.reason });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no request header risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.name || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  SENSITIVE,
  evaluateOutgoingHeaders,
  auditHeaderBatch,
  describeFindings,
};
