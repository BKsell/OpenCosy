'use strict';

const path = require('node:path');

const REASON = {
  OK: 'ok',
  EMPTY: 'path-empty',
  TOO_LONG: 'path-too-long',
  NUL_BYTE: 'path-nul-byte',
  TRAVERSAL: 'path-traversal',
  ABSOLUTE: 'path-absolute',
  UNC_PATH: 'path-unc',
  DRIVE_PATH: 'path-drive-letter',
  ADS: 'path-alternate-data-stream',
  OUTSIDE_ROOT: 'path-outside-root',
};

const MAX_PATH = 1024;

function evaluateRelativePath(value, options) {
  const opts = options || {};
  if (typeof value !== 'string' || value.length === 0) {
    return { ok: false, blocked: true, reason: REASON.EMPTY, path: '' };
  }
  if (value.length > MAX_PATH) return { ok: false, blocked: true, reason: REASON.TOO_LONG, path: value };
  if (value.includes('\u0000')) return { ok: false, blocked: true, reason: REASON.NUL_BYTE, path: value };
  const normalized = value.replace(/\\/g, '/');
  if (normalized.startsWith('//')) return { ok: false, blocked: true, reason: REASON.UNC_PATH, path: value };
  if (/^[A-Za-z]:/.test(normalized)) return { ok: false, blocked: true, reason: REASON.DRIVE_PATH, path: value };
  if (normalized.startsWith('/')) return { ok: false, blocked: true, reason: REASON.ABSOLUTE, path: value };
  if (normalized.split('/').some((seg) => seg === '..')) {
    return { ok: false, blocked: true, reason: REASON.TRAVERSAL, path: value };
  }
  if (opts.blockAlternateStream !== false && /:/.test(normalized)) {
    return { ok: false, blocked: true, reason: REASON.ADS, path: value };
  }
  return { ok: true, blocked: false, reason: REASON.OK, path: normalized, segments: normalized.split('/').filter(Boolean) };
}

function evaluateAbsolutePath(value, options) {
  const opts = options || {};
  if (typeof value !== 'string' || value.length === 0) {
    return { ok: false, blocked: true, reason: REASON.EMPTY, path: '' };
  }
  if (value.length > MAX_PATH) return { ok: false, blocked: true, reason: REASON.TOO_LONG, path: value };
  if (value.includes('\u0000')) return { ok: false, blocked: true, reason: REASON.NUL_BYTE, path: value };
  if (!path.isAbsolute(value)) {
    return { ok: false, blocked: true, reason: REASON.ABSOLUTE, path: value };
  }
  if (!opts.root) {
    return { ok: true, blocked: false, reason: REASON.OK, path: path.resolve(value) };
  }
  const root = path.resolve(String(opts.root));
  const target = path.resolve(value);
  const rel = path.relative(root, target);
  if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) {
    return { ok: false, blocked: true, reason: REASON.OUTSIDE_ROOT, path: target };
  }
  return { ok: true, blocked: false, reason: REASON.OK, path: target, relative: rel };
}

function auditPathBatch(list, options) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = options && options.absolute ? evaluateAbsolutePath(item, options) : evaluateRelativePath(item, options);
    if (result.blocked) {
      blocked += 1;
      findings.push({ path: result.path, reason: result.reason });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no path risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.path || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  evaluateRelativePath,
  evaluateAbsolutePath,
  auditPathBatch,
  describeFindings,
};
