'use strict';

const path = require('node:path');
const os = require('node:os');

const REASON = {
  OK: 'ok',
  EMPTY: 'file-path-empty',
  TOO_LONG: 'file-path-too-long',
  NUL_BYTE: 'file-path-nul',
  NOT_FILE_SCHEME: 'file-not-file-scheme',
  REMOTE_AUTHORITY: 'file-remote-authority',
  OUTSIDE_HOME: 'file-outside-allowed-root',
  SYSTEM_PATH: 'file-system-path',
  SENSITIVE_FILE: 'file-sensitive-name',
};

const MAX_PATH = 4096;
const SENSITIVE = new Set(['.ssh', 'id_rsa', 'id_ed25519', '.aws', '.gnupg', 'credentials', '.netrc', 'shadow', 'passwd']);
const SYSTEM_ROOTS = ['/etc/', '/usr/', '/bin/', '/sbin/', '/boot/', '/proc/', '/sys/', '/dev/', 'c:\\windows\\', 'c:\\program files\\'];

function evaluateFileUrl(value, options) {
  const opts = options || {};
  if (typeof value !== 'string' || value.length === 0) {
    return { ok: false, blocked: true, reason: REASON.EMPTY, path: '' };
  }
  if (value.length > MAX_PATH) return { ok: false, blocked: true, reason: REASON.TOO_LONG, path: '' };
  if (value.includes('\u0000')) return { ok: false, blocked: true, reason: REASON.NUL_BYTE, path: '' };
  let url;
  try {
    url = new URL(value);
  } catch (err) {
    return { ok: false, blocked: true, reason: REASON.NOT_FILE_SCHEME, path: value.slice(0, 128) };
  }
  if (url.protocol !== 'file:') {
    return { ok: false, blocked: true, reason: REASON.NOT_FILE_SCHEME, path: url.href };
  }
  if (url.hostname && url.hostname !== 'localhost') {
    return { ok: false, blocked: true, reason: REASON.REMOTE_AUTHORITY, path: url.href };
  }
  let filePath;
  try {
    filePath = decodeURIComponent(url.pathname);
  } catch (err) {
    return { ok: false, blocked: true, reason: REASON.NOT_FILE_SCHEME, path: url.pathname };
  }
  if (/^\/[A-Za-z]:/.test(filePath)) filePath = filePath.slice(1);
  const normalized = path.resolve(filePath);
  const lower = normalized.toLowerCase().replace(/\\/g, '/');
  if (SYSTEM_ROOTS.some((root) => lower.startsWith(root))) {
    return { ok: false, blocked: true, reason: REASON.SYSTEM_PATH, path: normalized };
  }
  const segments = lower.split('/');
  if (segments.some((seg) => SENSITIVE.has(seg))) {
    return { ok: false, blocked: true, reason: REASON.SENSITIVE_FILE, path: normalized };
  }
  const roots = Array.isArray(opts.roots) && opts.roots.length > 0 ? opts.roots : [os.homedir()];
  const allowed = roots.some((root) => {
    const rel = path.relative(path.resolve(String(root)), normalized);
    return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
  });
  if (!allowed) {
    return { ok: false, blocked: true, reason: REASON.OUTSIDE_HOME, path: normalized };
  }
  return { ok: true, blocked: false, reason: REASON.OK, path: normalized };
}

function auditFileAccessBatch(list, options) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateFileUrl(item, options);
    if (result.blocked) {
      blocked += 1;
      findings.push({ path: result.path, reason: result.reason });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no file access risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.path || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  evaluateFileUrl,
  auditFileAccessBatch,
  describeFindings,
};
