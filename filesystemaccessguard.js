'use strict';
const { describeReasonTable } = require('./reasontext');

const REASON = {
  OK: 'ok',
  MALFORMED: 'malformed',
  UNSAFE_SCHEME: 'unsafe-scheme',
  EMBEDDED_CREDENTIALS: 'embedded-credentials',
  PATH_TRAVERSAL: 'path-traversal',
  PUNYCODE_HOST: 'punycode-host',
  IP_LITERAL_HOST: 'ip-literal-host',
  OVERLONG: 'overlong',
  OPAQUE_ORIGIN: 'opaque-origin',
};

const MAX_URL_LENGTH = 2048;
const SECURE_SCHEMES = new Set(['https:', 'wss:']);
const LOCAL_SCHEMES = new Set(['http:', 'ws:']);
const OPAQUE_SCHEMES = new Set(['data:', 'blob:', 'filesystem:', 'javascript:', 'vbscript:']);
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);

function isLoopback(hostname) {
  if (!hostname) return false;
  const lower = hostname.toLowerCase();
  if (LOOPBACK_HOSTS.has(lower)) return true;
  if (lower.startsWith('127.')) return true;
  return false;
}

function isIPLiteral(hostname) {
  if (!hostname) return false;
  const lower = hostname.replace(/^\[|\]$/g, '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(lower)) return true;
  if (lower.includes(':')) return true;
  return false;
}

function hasEncodedTraversal(rawUrl) {
  const lower = String(rawUrl || '').toLowerCase();
  if (lower.includes('..')) return true;
  if (lower.includes('%2e%2e')) return true;
  if (lower.includes('%2f%2e')) return true;
  return false;
}

function inspectFileSystemAccess(rawUrl) {
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
  if (!SECURE_SCHEMES.has(parsed.protocol) && !LOCAL_SCHEMES.has(parsed.protocol)) {
    return { allowed: false, reason: REASON.UNSAFE_SCHEME };
  }
  if (LOCAL_SCHEMES.has(parsed.protocol) && !isLoopback(parsed.hostname)) {
    return { allowed: false, reason: REASON.UNSAFE_SCHEME };
  }
  if (parsed.username || parsed.password) {
    return { allowed: false, reason: REASON.EMBEDDED_CREDENTIALS };
  }
  if (hasEncodedTraversal(text)) {
    return { allowed: false, reason: REASON.PATH_TRAVERSAL };
  }
  if (parsed.hostname.toLowerCase().startsWith('xn--')) {
    return { allowed: false, reason: REASON.PUNYCODE_HOST };
  }
  if (isIPLiteral(parsed.hostname) && !isLoopback(parsed.hostname)) {
    return { allowed: false, reason: REASON.IP_LITERAL_HOST };
  }
  return { allowed: true, reason: REASON.OK };
}

const describeReason = describeReasonTable({
    [REASON.OK]: '文件系统访问请求来源安全',
    [REASON.MALFORMED]: '文件系统访问请求地址非法',
    [REASON.UNSAFE_SCHEME]: '文件系统访问仅允许安全来源',
    [REASON.EMBEDDED_CREDENTIALS]: '来源地址内嵌凭据，拒绝文件系统访问',
    [REASON.PATH_TRAVERSAL]: '来源地址含路径穿越片段，拒绝文件系统访问',
    [REASON.PUNYCODE_HOST]: '来源主机为 punycode 同形域名，拒绝文件系统访问',
    [REASON.IP_LITERAL_HOST]: '来源主机为裸 IP，拒绝文件系统访问',
    [REASON.OVERLONG]: '来源地址超长，拒绝文件系统访问',
    [REASON.OPAQUE_ORIGIN]: '来源为不透明来源，拒绝文件系统访问',
  }, '文件系统访问来源未识别状态');

function applyFileSystemAccessGuard(url) {
  const result = inspectFileSystemAccess(url);
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
  inspectFileSystemAccess,
  applyFileSystemAccessGuard,
  describeReason,
};
