'use strict';

const REASON = {
  OK: 'ok',
  MALFORMED: 'malformed',
  UNSAFE_SCHEME: 'unsafe-scheme',
  OPAQUE_ORIGIN: 'opaque-origin',
  EMBEDDED_CREDENTIALS: 'embedded-credentials',
  RP_ID_MISMATCH: 'rp-id-mismatch',
  RP_ID_SUFFIX_AMBIGUOUS: 'rp-id-suffix-ambiguous',
  PUNYCODE_RP_ID: 'punycode-rp-id',
  OVERLONG: 'overlong',
};

const MAX_URL_LENGTH = 2048;
const SECURE_SCHEMES = new Set(['https:', 'wss:']);
const OPAQUE_SCHEMES = new Set(['data:', 'blob:', 'filesystem:', 'javascript:', 'vbscript:', 'file:']);
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

function isLoopback(hostname) {
  if (!hostname) return false;
  const lower = hostname.toLowerCase();
  if (LOOPBACK_HOSTS.has(lower)) return true;
  return lower.startsWith('127.');
}

function normalizeRpId(rpId) {
  if (typeof rpId !== 'string') return '';
  return rpId.trim().toLowerCase().replace(/^\.+|\.+$/g, '');
}

function rpIdMatchesHost(rpId, hostname) {
  const host = String(hostname || '').toLowerCase();
  if (!rpId || !host) return false;
  if (host === rpId) return true;
  if (host.endsWith(`.${rpId}`)) {
    const prefix = host.slice(0, host.length - rpId.length - 1);
    if (prefix.includes('.')) return false;
    return prefix.length > 0;
  }
  return false;
}

function inspectCredentialRequest(rawUrl, options) {
  if (typeof rawUrl !== 'string') return { allowed: false, reason: REASON.MALFORMED };
  const text = rawUrl.trim();
  if (!text) return { allowed: false, reason: REASON.MALFORMED };
  if (text.length > MAX_URL_LENGTH) return { allowed: false, reason: REASON.OVERLONG };
  let parsed = null;
  try {
    parsed = new URL(text);
  } catch (err) {
    return { allowed: false, reason: REASON.MALFORMED };
  }
  if (OPAQUE_SCHEMES.has(parsed.protocol)) {
    return { allowed: false, reason: REASON.OPAQUE_ORIGIN };
  }
  if (!SECURE_SCHEMES.has(parsed.protocol) && !isLoopback(parsed.hostname)) {
    return { allowed: false, reason: REASON.UNSAFE_SCHEME };
  }
  if (parsed.username || parsed.password) {
    return { allowed: false, reason: REASON.EMBEDDED_CREDENTIALS };
  }
  const rpId = normalizeRpId(options && options.rpId);
  if (!rpId) {
    return { allowed: true, reason: REASON.OK };
  }
  if (rpId.startsWith('xn--') || rpId.includes('.xn--')) {
    return { allowed: false, reason: REASON.PUNYCODE_RP_ID };
  }
  if (!rpId.includes('.') && !isLoopback(rpId)) {
    return { allowed: false, reason: REASON.RP_ID_SUFFIX_AMBIGUOUS };
  }
  if (!rpIdMatchesHost(rpId, parsed.hostname)) {
    return { allowed: false, reason: REASON.RP_ID_MISMATCH };
  }
  return { allowed: true, reason: REASON.OK };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return '凭据请求来源与依赖方标识一致';
    case REASON.MALFORMED:
      return '凭据请求地址非法';
    case REASON.UNSAFE_SCHEME:
      return '凭据请求仅允许安全来源';
    case REASON.OPAQUE_ORIGIN:
      return '凭据请求来自不透明来源，已拒绝';
    case REASON.EMBEDDED_CREDENTIALS:
      return '来源地址内嵌凭据，已拒绝';
    case REASON.RP_ID_MISMATCH:
      return '依赖方标识与来源主机不匹配，已拒绝';
    case REASON.RP_ID_SUFFIX_AMBIGUOUS:
      return '依赖方标识为公共后缀，已拒绝';
    case REASON.PUNYCODE_RP_ID:
      return '依赖方标识为 punycode 同形域名，已拒绝';
    case REASON.OVERLONG:
      return '凭据请求地址超长，已拒绝';
    default:
      return '凭据请求未识别状态';
  }
}

function applyCredentialRequestGuard(url, options) {
  const result = inspectCredentialRequest(url, options);
  return {
    changed: !result.allowed,
    allowed: result.allowed,
    reason: result.reason,
    findings: [{ reason: result.reason, allowed: result.allowed }],
  };
}

module.exports = {
  REASON,
  MAX_URL_LENGTH,
  inspectCredentialRequest,
  applyCredentialRequestGuard,
  describeReason,
};
