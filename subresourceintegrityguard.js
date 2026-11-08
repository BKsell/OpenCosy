'use strict';

const REASON = {
  OK: 'ok',
  INVALID: 'invalid-resource',
  INSECURE: 'insecure-transport',
  MISSING_INTEGRITY: 'missing-integrity',
  WEAK_ALGORITHM: 'weak-integrity-algorithm',
  CREDENTIALS: 'url-credentials',
  DATA_URI: 'inline-data-uri',
};

const MAX_URL = 8192;
const MAX_INTEGRITY = 256;
const STRONG = new Set(['sha256', 'sha384', 'sha512']);
const ACTIVE_TAGS = new Set(['script', 'link', 'iframe', 'object', 'embed']);

function parseResource(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_URL) return null;
  try {
    return new URL(value);
  } catch (err) {
    return null;
  }
}

function parseIntegrity(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_INTEGRITY) return null;
  const tokens = value.trim().split(/\s+/);
  if (tokens.length === 0) return null;
  const algorithms = [];
  for (const token of tokens) {
    const idx = token.indexOf('-');
    if (idx <= 0) return null;
    const algorithm = token.slice(0, idx).toLowerCase();
    const digest = token.slice(idx + 1);
    if (!STRONG.has(algorithm)) return { algorithm, strong: false };
    if (!/^[A-Za-z0-9+/=]{16,}$/.test(digest)) return null;
    algorithms.push(algorithm);
  }
  return { algorithm: algorithms[0] || 'sha256', strong: true };
}

function evaluateSubresource(input, options) {
  const opts = options || {};
  const tag = String((input && input.tag) || 'script').toLowerCase();
  const src = input && input.src;
  const url = typeof src === 'string' && src.startsWith('data:') ? null : parseResource(src);
  if (typeof src === 'string' && src.startsWith('data:')) {
    return { ok: false, blocked: true, reason: REASON.DATA_URI, url: null };
  }
  if (!url) return { ok: false, blocked: true, reason: REASON.INVALID, url: null };
  if (url.username || url.password) {
    return { ok: false, blocked: true, reason: REASON.CREDENTIALS, url: url.href };
  }
  const local = url.protocol === 'file:' || url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  const secure = url.protocol === 'https:' || url.protocol === 'wss:' || local;
  if (!secure) return { ok: false, blocked: true, reason: REASON.INSECURE, url: url.href };
  if (!ACTIVE_TAGS.has(tag)) return { ok: true, blocked: false, reason: REASON.OK, url: url.href };
  if (local && opts.requireLocalIntegrity !== true) {
    return { ok: true, blocked: false, reason: REASON.OK, url: url.href };
  }
  const integrity = parseIntegrity(input && input.integrity);
  if (!integrity) return { ok: false, blocked: true, reason: REASON.MISSING_INTEGRITY, url: url.href };
  if (!integrity.strong) {
    return { ok: false, blocked: true, reason: REASON.WEAK_ALGORITHM, url: url.href, algorithm: integrity.algorithm };
  }
  return { ok: true, blocked: false, reason: REASON.OK, url: url.href, algorithm: integrity.algorithm };
}

function auditSubresourceBatch(list, options) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateSubresource(item, options);
    if (result.blocked) blocked += 1;
    if (result.blocked) findings.push({ src: item && item.src, reason: result.reason, algorithm: result.algorithm });
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no subresource risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.src || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  evaluateSubresource,
  auditSubresourceBatch,
  describeFindings,
  parseIntegrity,
};
