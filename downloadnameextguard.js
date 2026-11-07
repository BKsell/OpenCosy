'use strict';

const REASON = {
  ok: 'ok',
  doubleExtension: 'double-extension',
  bidiOverride: 'bidi-override',
  controlChars: 'control-chars',
  trailingDotSpace: 'trailing-dot-space',
  reservedDevice: 'reserved-device-name',
  hiddenFile: 'hidden-executable',
  tooLong: 'name-too-long',
  malformed: 'malformed-disposition',
};

const EXECUTABLE_EXTENSIONS = new Set([
  'exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'msi', 'msp', 'cpl', 'hta',
  'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'ps1', 'ps2', 'jar', 'lnk', 'reg', 'dll',
]);

const DECOY_EXTENSIONS = new Set([
  'pdf', 'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'txt', 'rtf', 'csv',
  'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar', '7z',
  'mp3', 'mp4', 'avi', 'mkv', 'mov', 'wav', 'flac',
]);

const RESERVED_DEVICE_NAMES = new Set([
  'con', 'prn', 'aux', 'nul',
  'com1', 'com2', 'com3', 'com4', 'com5', 'com6', 'com7', 'com8', 'com9',
  'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9',
]);

const MAX_NAME_LENGTH = 200;

function hasBidiOverride(text) {
  return /[\u202a-\u202e\u2066-\u2069]/.test(String(text || ''));
}

function hasControlChars(text) {
  return /[\u0000-\u001f\u007f]/.test(String(text || ''));
}

function extensionOf(name) {
  const idx = name.lastIndexOf('.');
  if (idx <= 0 || idx === name.length - 1) return '';
  return name.slice(idx + 1).toLowerCase();
}

function baseNameOf(name) {
  const idx = name.lastIndexOf('.');
  if (idx <= 0) return name;
  return name.slice(0, idx);
}

function inspectDownloadName(name) {
  const raw = String(name || '');
  if (!raw) return { reason: REASON.malformed, dangerous: true, sanitized: 'download.download' };
  const stripped = raw.replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, '');
  const fallback = stripped.replace(/[. ]+/g, '').slice(0, 40) || 'download';
  if (hasBidiOverride(raw)) {
    return { reason: REASON.bidiOverride, dangerous: true, sanitized: `${fallback}.download` };
  }
  if (hasControlChars(raw)) {
    return { reason: REASON.controlChars, dangerous: true, sanitized: `${fallback}.download` };
  }
  if (raw.length > MAX_NAME_LENGTH) {
    return { reason: REASON.tooLong, dangerous: true, sanitized: 'download.download' };
  }
  if (raw.startsWith('.') && raw.replace(/^[.]+/, '') !== '') {
    return { reason: REASON.hiddenFile, dangerous: true, sanitized: `${fallback.replace(/^[.]+/, '') || 'download'}.download` };
  }
  if (/[. ]$/.test(raw)) {
    return { reason: REASON.trailingDotSpace, dangerous: true, sanitized: `${fallback}.download` };
  }
  const ext = extensionOf(raw);
  const base = baseNameOf(raw).toLowerCase();
  if (RESERVED_DEVICE_NAMES.has(base)) {
    return { reason: REASON.reservedDevice, dangerous: true, sanitized: `${base}.download` };
  }
  if (EXECUTABLE_EXTENSIONS.has(ext)) {
    const decoyExt = extensionOf(baseNameOf(raw)).toLowerCase();
    if (DECOY_EXTENSIONS.has(decoyExt)) {
      return { reason: REASON.doubleExtension, dangerous: true, sanitized: `${baseNameOf(baseNameOf(raw)) || 'download'}.download` };
    }
    return { reason: REASON.ok, dangerous: false, sanitized: raw };
  }
  return { reason: REASON.ok, dangerous: false, sanitized: raw };
}

function parseDisposition(value) {
  const text = String(value || '');
  const semi = text.indexOf(';');
  const type = (semi < 0 ? text : text.slice(0, semi)).trim().toLowerCase();
  if (!/^[a-z0-9-]+$/.test(type)) return null;
  let filename = null;
  const quoted = /filename\s*=\s*"([^"]*)"/i.exec(text);
  if (quoted) filename = quoted[1];
  if (filename === null) {
    const plain = /filename\s*=\s*([^;]+)/i.exec(text);
    if (plain) filename = plain[1].trim();
  }
  if (filename === null) {
    const star = /filename\*\s*=\s*[^']*''([^;]+)/i.exec(text);
    if (star) {
      try {
        filename = decodeURIComponent(star[1].trim());
      } catch {
        return null;
      }
    }
  }
  return { type, filename };
}

function headerValues(headers, name) {
  const target = name.toLowerCase();
  for (const key of Object.keys(headers || {})) {
    if (key.toLowerCase() !== target) continue;
    const value = headers[key];
    if (Array.isArray(value)) return value.slice();
    if (typeof value === 'string') return [value];
  }
  return [];
}

function replaceHeader(headers, name, values) {
  for (const key of Object.keys(headers || {})) {
    if (key.toLowerCase() === name.toLowerCase()) delete headers[key];
  }
  if (values.length) headers[name] = values;
}

function quoteFilename(name) {
  return `"${String(name).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

function applyDownloadNameGuard(headers) {
  const values = headerValues(headers, 'content-disposition');
  if (!values.length) return { changed: false, verdict: { reason: REASON.ok }, names: [] };
  const names = [];
  const rewritten = [];
  let reason = REASON.ok;
  let forcedAttachment = false;
  for (const value of values) {
    const parsed = parseDisposition(value);
    if (!parsed) {
      reason = reason === REASON.ok ? REASON.malformed : reason;
      rewritten.push('attachment; filename="download.download"');
      names.push('download.download');
      forcedAttachment = true;
      continue;
    }
    if (!parsed.filename) {
      rewritten.push(value);
      continue;
    }
    const verdict = inspectDownloadName(parsed.filename);
    names.push(verdict.sanitized);
    if (verdict.dangerous) {
      reason = reason === REASON.ok ? verdict.reason : reason;
      forcedAttachment = true;
      rewritten.push(`attachment; filename=${quoteFilename(verdict.sanitized)}`);
      continue;
    }
    rewritten.push(value);
  }
  const changed = forcedAttachment || reason !== REASON.ok;
  if (changed) replaceHeader(headers, 'Content-Disposition', rewritten);
  return { changed, verdict: { reason }, names, forcedAttachment };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.ok: return 'download name acceptable';
    case REASON.doubleExtension: return 'executable hidden behind a decoy extension';
    case REASON.bidiOverride: return 'name carries a bidi override';
    case REASON.controlChars: return 'name carries control characters';
    case REASON.trailingDotSpace: return 'name ends with dots or spaces';
    case REASON.reservedDevice: return 'name maps to a reserved device';
    case REASON.hiddenFile: return 'name resolves to a hidden file';
    case REASON.tooLong: return 'name exceeds the length budget';
    case REASON.malformed: return 'Content-Disposition cannot be parsed';
    default: return 'unknown download name verdict';
  }
}

module.exports = {
  REASON,
  MAX_NAME_LENGTH,
  EXECUTABLE_EXTENSIONS,
  DECOY_EXTENSIONS,
  inspectDownloadName,
  parseDisposition,
  applyDownloadNameGuard,
  describeReason,
};
