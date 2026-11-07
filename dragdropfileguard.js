'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'drop-empty',
  TOO_MANY_FILES: 'drop-too-many-files',
  UNTRUSTED_SOURCE: 'drop-untrusted-source',
  EXECUTABLE_FILE: 'drop-executable',
  SYMLINK_ENTRY: 'drop-symlink',
  OUTSIDE_DRAG_ROOT: 'drop-outside-root',
  DLL_PAYLOAD: 'drop-dll-payload',
};

const MAX_FILES = 200;
const DANGEROUS = new Set(['.dll', '.exe', '.scr', '.cpl', '.msi', '.sys', '.bat', '.cmd', '.ps1', '.jar']);

function evaluateDrop(payload, options) {
  const item = payload || {};
  const opts = options || {};
  const files = Array.isArray(item.files) ? item.files : [];
  const filesRoot = opts.filesRoot ? String(opts.filesRoot) : '';
  if (files.length === 0) return { ok: false, blocked: true, reason: REASON.EMPTY, count: 0 };
  if (files.length > MAX_FILES) return { ok: false, blocked: true, reason: REASON.TOO_MANY_FILES, count: files.length };
  if (item.trusted !== true) {
    return { ok: false, blocked: true, reason: REASON.UNTRUSTED_SOURCE, count: files.length };
  }
  for (const file of files) {
    const name = String((file && (file.path || file.name)) || '');
    if (name === '') return { ok: false, blocked: true, reason: REASON.EMPTY, count: files.length };
    const lower = name.toLowerCase();
    const ext = /\.[a-z0-9]+$/.exec(lower);
    if (ext && DANGEROUS.has(ext[0])) {
      return { ok: false, blocked: true, reason: ext[0] === '.dll' ? REASON.DLL_PAYLOAD : REASON.EXECUTABLE_FILE, name };
    }
    if (file && file.isSymlink === true) return { ok: false, blocked: true, reason: REASON.SYMLINK_ENTRY, name };
    if (filesRoot && (lower.startsWith(filesRoot.toLowerCase() + '/') === false && lower.startsWith(filesRoot.toLowerCase() + '\\') === false)) {
      if (!lower.startsWith(filesRoot.toLowerCase())) return { ok: false, blocked: true, reason: REASON.OUTSIDE_DRAG_ROOT, name };
    }
  }
  return { ok: true, blocked: false, reason: REASON.OK, count: files.length };
}

function evaluateDragOver(event) {
  const ev = event || {};
  const types = Array.isArray(ev.types) ? ev.types : [];
  const hasFiles = ev.files === true || types.includes('Files');
  return {
    ok: !hasFiles || ev.preventDefault === true,
    blocked: hasFiles && ev.preventDefault !== true,
    reason: hasFiles && ev.preventDefault !== true ? REASON.UNTRUSTED_SOURCE : REASON.OK,
    files: hasFiles,
    dragging: ev.dragging === true,
  };
}

function auditDropBatch(list, options) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateDrop(item, options && options[0] ? { filesRoot: options[0] } : options);
    if (result.blocked) {
      blocked += 1;
      findings.push({ reason: result.reason, name: result.name || '', count: result.count || 0 });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no drag drop risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.name || f.count || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  evaluateDrop,
  evaluateDragOver,
  auditDropBatch,
  describeFindings,
};
