'use strict';

const path = require('node:path');

const REASON = {
  OK: 'ok',
  EMPTY: 'download-name-empty',
  TOO_LONG: 'download-name-too-long',
  NUL_BYTE: 'download-name-nul',
  PATH_SEPARATOR: 'download-name-separator',
  EXECUTABLE: 'download-executable',
  DOUBLE_EXTENSION: 'download-double-extension',
  HIDDEN_EXECUTABLE: 'download-hidden-executable',
  SCRIPT_TYPE: 'download-script-type',
};

const MAX_NAME = 180;
const EXECUTABLE = new Set([
  '.exe', '.msi', '.bat', '.cmd', '.com', '.scr', '.pif', '.ps1', '.psm1',
  '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.jar', '.lnk',
  '.dll', '.sys', '.reg', '.app', '.dmg', '.pkg', '.deb', '.rpm',
]);
const SCRIPT_MIME = new Set(['application/javascript', 'text/javascript', 'application/x-sh', 'application/x-msdownload']);

function classifyName(name) {
  const lower = name.toLowerCase();
  const parts = lower.split('.').filter(Boolean);
  if (parts.length === 0) return { ext: '', double: false };
  const ext = '.' + parts[parts.length - 1];
  const prior = parts.length > 1 ? '.' + parts[parts.length - 2] : '';
  const double = EXECUTABLE.has(prior) || ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'png', 'txt', 'zip'].includes(parts[parts.length - 2]);
  return { ext, double };
}

function evaluateDownloadName(name, options) {
  if (typeof name !== 'string' || name.length === 0) {
    return { ok: false, blocked: true, reason: REASON.EMPTY, name: name || '' };
  }
  if (name.length > MAX_NAME) return { ok: false, blocked: true, reason: REASON.TOO_LONG, name };
  if (name.includes('\u0000')) return { ok: false, blocked: true, reason: REASON.NUL_BYTE, name };
  if (name.includes('/') || name.includes('\\')) {
    return { ok: false, blocked: true, reason: REASON.PATH_SEPARATOR, name };
  }
  if (name.startsWith('.') && name.length > 1) {
    const { ext } = classifyName(name);
    if (EXECUTABLE.has(ext)) return { ok: false, blocked: true, reason: REASON.HIDDEN_EXECUTABLE, name };
  }
  const { ext, double } = classifyName(name);
  if (EXECUTABLE.has(ext)) {
    if (options && options.allowExecutable === true) {
      return { ok: true, blocked: false, reason: REASON.OK, name, ext };
    }
    return { ok: false, blocked: true, reason: REASON.EXECUTABLE, name, ext };
  }
  if (double && options && options.blockDoubleExtension === true) {
    return { ok: false, blocked: true, reason: REASON.DOUBLE_EXTENSION, name, ext };
  }
  return { ok: true, blocked: false, reason: REASON.OK, name, ext };
}

function evaluateDownload(input, options) {
  const item = input || {};
  const base = evaluateDownloadName(item.filename, options);
  if (base.blocked) return base;
  if (item.mimeType && SCRIPT_MIME.has(String(item.mimeType).toLowerCase()) && options && options.allowScriptMime !== true) {
    return { ok: false, blocked: true, reason: REASON.SCRIPT_TYPE, name: base.name, ext: base.ext };
  }
  if (item.contentDisposition && /filename\*=utf-8''%2e%2e/i.test(String(item.contentDisposition))) {
    return { ok: false, blocked: true, reason: REASON.PATH_SEPARATOR, name: base.name, ext: base.ext };
  }
  return { ok: true, blocked: false, reason: REASON.OK, name: base.name, ext: base.ext };
}

function auditDownloadBatch(list, options) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateDownload(item, options);
    if (result.blocked) {
      blocked += 1;
      findings.push({ name: result.name, reason: result.reason, ext: result.ext || '' });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no download name risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.name || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  evaluateDownloadName,
  evaluateDownload,
  auditDownloadBatch,
  describeFindings,
  classifyName,
};
