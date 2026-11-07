'use strict';

const path = require('node:path');

const REASON = {
  OK: 'ok',
  EMPTY: 'preload-empty',
  RELATIVE: 'preload-relative',
  OUTSIDE_APP: 'preload-outside-app',
  WRONG_EXTENSION: 'preload-wrong-extension',
  TEMP_DIR: 'preload-in-temp',
  NUL_BYTE: 'preload-nul-byte',
  TRAVERSAL: 'preload-traversal',
};

const MAX_PATH = 4096;
const ALLOWED_EXT = new Set(['.js', '.cjs', '.mjs']);
const TEMP_HINTS = ['/tmp/', '/var/tmp/', '/dev/shm/', '\\temp\\', '\\tmp\\'];

function hasTraversal(value) {
  const normalized = value.replace(/\\/g, '/');
  return normalized.split('/').some((seg) => seg === '..');
}

function evaluatePreload(value, options) {
  const opts = options || {};
  if (value === null || value === undefined || value === '') {
    return { ok: true, blocked: false, reason: REASON.EMPTY, path: null };
  }
  if (typeof value !== 'string' || value.length > MAX_PATH) {
    return { ok: false, blocked: true, reason: REASON.WRONG_EXTENSION, path: null };
  }
  if (value.includes('\u0000')) {
    return { ok: false, blocked: true, reason: REASON.NUL_BYTE, path: value };
  }
  if (hasTraversal(value)) {
    return { ok: false, blocked: true, reason: REASON.TRAVERSAL, path: value };
  }
  if (!path.isAbsolute(value)) {
    return { ok: false, blocked: true, reason: REASON.RELATIVE, path: value };
  }
  const ext = path.extname(value).toLowerCase();
  if (!ALLOWED_EXT.has(ext)) {
    return { ok: false, blocked: true, reason: REASON.WRONG_EXTENSION, path: value };
  }
  const lower = value.toLowerCase().replace(/\\/g, '/');
  if (TEMP_HINTS.some((hint) => lower.includes(hint.replace(/\\/g, '/')))) {
    return { ok: false, blocked: true, reason: REASON.TEMP_DIR, path: value };
  }
  if (opts.appRoot) {
    const root = path.resolve(String(opts.appRoot));
    const target = path.resolve(value);
    const rel = path.relative(root, target);
    if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) {
      return { ok: false, blocked: true, reason: REASON.OUTSIDE_APP, path: value };
    }
  }
  return { ok: true, blocked: false, reason: REASON.OK, path: value };
}

function evaluateBrowserWindow(preferences, options) {
  const prefs = preferences || {};
  const result = evaluatePreload(prefs.preload, options);
  if (result.blocked) return { ...result, field: 'preload' };
  if (prefs.nodeIntegration === true && options && options.allowNodeIntegration !== true) {
    return { ok: false, blocked: true, reason: REASON.OUTSIDE_APP, path: prefs.preload || null, field: 'nodeIntegration' };
  }
  return { ok: true, blocked: false, reason: REASON.OK, path: result.path };
}

function auditPreloadBatch(list, options) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluatePreload(item, options);
    if (result.blocked) {
      blocked += 1;
      findings.push({ reason: result.reason, path: result.path });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no preload risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.path || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  evaluatePreload,
  evaluateBrowserWindow,
  auditPreloadBatch,
  describeFindings,
};
