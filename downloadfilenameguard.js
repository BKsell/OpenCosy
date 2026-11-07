'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'empty-name',
  PATH_TRAVERSAL: 'path-separator',
  CONTROL_CHARS: 'control-characters',
  RESERVED: 'reserved-device-name',
  TRAILING_DOT: 'trailing-dot-or-space',
  BIDI_OVERRIDE: 'bidi-override',
  TOO_LONG: 'name-too-long',
  HIDDEN: 'hidden-file',
  DOUBLE_EXTENSION: 'double-extension',
};

const RESERVED_NAMES = new Set(['con', 'prn', 'aux', 'nul', 'com1', 'com2', 'com3', 'com4', 'com5', 'com6', 'com7', 'com8', 'com9', 'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9']);
const BIDI = /[\u202a-\u202e\u2066-\u2069]/;
const DANGEROUS_EXT = new Set(['exe', 'scr', 'com', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'jse', 'wsf', 'wsh', 'msi', 'lnk', 'hta', 'reg', 'jar', 'pif', 'cpl']);

function splitExt(name) {
  const idx = name.lastIndexOf('.');
  if (idx <= 0 || idx === name.length - 1) return { base: name, ext: '' };
  return { base: name.slice(0, idx), ext: name.slice(idx + 1) };
}

function sanitizeFilename(input, options) {
  const opts = options && typeof options === 'object' ? options : {};
  const maxLength = Number(opts.maxLength) || 120;
  const original = typeof input === 'string' ? input : '';
  if (!original.trim()) return { name: 'download', changed: true, reason: REASON.EMPTY };
  let name = original.replace(/\\/g, '/').split('/').pop();
  let reason = REASON.OK;
  if (name !== original) reason = REASON.PATH_TRAVERSAL;
  name = name.replace(/[\u0000-\u001f\u007f]/g, '').trim();
  if (BIDI.test(name)) {
    name = name.replace(BIDI, '');
    reason = reason === REASON.OK ? REASON.BIDI_OVERRIDE : reason;
  }
  name = name.replace(/[<>:"|?*]/g, '_');
  if (/^\.+$/.test(name)) name = 'download';
  if (name.startsWith('.')) {
    name = '_' + name.slice(1);
    if (reason === REASON.OK) reason = REASON.HIDDEN;
  }
  const { base, ext } = splitExt(name);
  if (RESERVED_NAMES.has(base.toLowerCase())) {
    name = base + '_' + (ext || 'dat');
    if (reason === REASON.OK) reason = REASON.RESERVED;
  }
  while (name.endsWith('.') || name.endsWith(' ')) {
    name = name.slice(0, -1);
    if (reason === REASON.OK) reason = REASON.TRAILING_DOT;
  }
  if (name.length > maxLength) {
    const parts = splitExt(name);
    const keep = Math.max(1, maxLength - (parts.ext ? parts.ext.length + 1 : 0));
    name = parts.base.slice(0, keep) + (parts.ext ? '.' + parts.ext : '');
    if (reason === REASON.OK) reason = REASON.TOO_LONG;
  }
  if (!name) return { name: 'download', changed: true, reason: REASON.EMPTY };
  return { name, changed: name !== original, reason };
}

function applyDownloadFilenameGuard(request) {
  const req = request && typeof request === 'object' ? request : {};
  const result = sanitizeFilename(req.filename, { maxLength: req.maxLength });
  const ext = splitExt(result.name).ext.toLowerCase();
  const risky = DANGEROUS_EXT.has(ext);
  return {
    name: result.name,
    changed: result.changed,
    reason: result.reason,
    riskyExtension: risky,
    forceConfirm: risky || result.reason === REASON.DOUBLE_EXTENSION,
  };
}

function auditFilenameBatch(names, options) {
  const list = Array.isArray(names) ? names : [];
  const findings = [];
  let rewritten = 0;
  for (const item of list) {
    const result = sanitizeFilename(item, options);
    if (result.changed) rewritten += 1;
    if (result.reason !== REASON.OK) findings.push({ name: String(item || '').slice(0, 80), reason: result.reason, fixed: result.name });
  }
  const limit = Number(options && options.maxFindings) || 10;
  return { rewritten, total: list.length, findings: findings.slice(0, limit) };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no filename risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applyDownloadFilenameGuard,
  auditFilenameBatch,
  describeFindings,
  sanitizeFilename,
};
