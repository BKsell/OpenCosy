'use strict';

const path = require('node:path');

const REASON = {
  OK: 'ok',
  EMPTY: 'download-path-empty',
  NOT_ABSOLUTE: 'download-path-relative',
  TRAVERSAL: 'download-path-traversal',
  NUL_BYTE: 'download-path-nul',
  TEMP_DIR: 'download-path-temp',
  SYSTEM_DIR: 'download-path-system',
  OUTSIDE_TARGET: 'download-path-outside-target',
  EXECUTABLE_DIR: 'download-path-executable-dir',
};

const MAX_PATH = 4096;
const SYSTEM = ['/etc/', '/usr/', '/bin/', '/var/lib/', 'c:\\windows\\', 'c:\\programdata\\'];
const EXEC_DIRS = ['startup', 'start menu', 'autorun'];

function evaluateDownloadPath(value, options) {
  const opts = options || {};
  if (typeof value !== 'string' || value.length === 0) {
    return { ok: false, blocked: true, reason: REASON.EMPTY, path: '' };
  }
  if (value.length > MAX_PATH) return { ok: false, blocked: true, reason: REASON.EMPTY, path: '' };
  if (value.includes('\u0000')) return { ok: false, blocked: true, reason: REASON.NUL_BYTE, path: value };
  if (!path.isAbsolute(value)) return { ok: false, blocked: true, reason: REASON.NOT_ABSOLUTE, path: value };
  const normalized = path.resolve(value);
  const lower = normalized.toLowerCase().replace(/\\/g, '/');
  if (lower.split('/').some((seg) => seg === '..')) {
    return { ok: false, blocked: true, reason: REASON.TRAVERSAL, path: normalized };
  }
  if (SYSTEM.some((root) => lower.startsWith(root.replace(/\\/g, '/')))) {
    return { ok: false, blocked: true, reason: REASON.SYSTEM_DIR, path: normalized };
  }
  if (EXEC_DIRS.some((dir) => lower.includes('/' + dir + '/'))) {
    return { ok: false, blocked: true, reason: REASON.EXECUTABLE_DIR, path: normalized };
  }
  if (/^\/(tmp|var\/tmp|dev\/shm)\//.test(lower)) {
    if (opts.allowTemp !== true) return { ok: false, blocked: true, reason: REASON.TEMP_DIR, path: normalized };
  }
  if (opts.targetDir) {
    const target = path.resolve(String(opts.targetDir));
    const rel = path.relative(target, normalized);
    if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) {
      return { ok: false, blocked: true, reason: REASON.OUTSIDE_TARGET, path: normalized };
    }
  }
  return { ok: true, blocked: false, reason: REASON.OK, path: normalized };
}

function evaluateDownloadTarget(request) {
  const req = request || {};
  const candidates = [req.savePath, req.directory].filter((item) => typeof item === 'string' && item.length > 0);
  if (candidates.length === 0) {
    return { ok: false, blocked: true, reason: REASON.EMPTY, path: '' };
  }
  let last = null;
  for (const candidate of candidates) {
    last = evaluateDownloadPath(candidate, req);
    if (last.blocked) return last;
  }
  return last;
}

function auditDownloadPathBatch(list) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateDownloadTarget(item);
    if (result.blocked) {
      blocked += 1;
      findings.push({ path: result.path, reason: result.reason });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no download path risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.path || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  evaluateDownloadPath,
  evaluateDownloadTarget,
  auditDownloadPathBatch,
  describeFindings,
};
