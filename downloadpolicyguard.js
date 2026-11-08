'use strict';

const REASON = {
  OK: 'ok',
  MISSING_NAME: 'missing-name',
  CONTROL_CHARS: 'control-characters',
  BIDI_OVERRIDE: 'bidi-override',
  TRAILING_DOT: 'trailing-dot',
  TOO_LONG: 'too-long',
  DANGEROUS_EXTENSION: 'dangerous-extension',
  DOUBLE_EXTENSION: 'double-extension',
  MIME_MISMATCH: 'mime-mismatch',
  TOO_LARGE: 'too-large',
  INSECURE_URL: 'insecure-url',
};

const MAX_NAME_LENGTH = 255;
const MAX_SIZE = 1024 * 1024 * 1024;
const DANGEROUS_EXTENSIONS = new Set([
  'exe', 'msi', 'msp', 'bat', 'cmd', 'com', 'scr', 'pif', 'cpl', 'hta', 'jar', 'jnlp',
  'ps1', 'psm1', 'vbs', 'vbe', 'wsf', 'wsh', 'reg', 'lnk', 'url', 'apk', 'dmg', 'pkg',
  'deb', 'rpm', 'app', 'sh', 'bash', 'zsh', 'py', 'rb', 'pl', 'php', 'asp', 'aspx', 'jsp',
]);
const DOCUMENT_EXTENSIONS = new Set(['pdf', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'txt', 'csv', 'json', 'zip', 'docx', 'xlsx', 'pptx']);
const MIME_BY_EXTENSION = {
  pdf: 'application/pdf',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp',
  txt: 'text/plain',
  csv: 'text/csv',
  json: 'application/json',
  zip: 'application/zip',
};

function hasControlChars(value) {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

function hasBidiOverride(value) {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if ((code >= 0x202a && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069)) return true;
  }
  return false;
}

function extensionOf(name) {
  const dot = name.lastIndexOf('.');
  if (dot <= 0 || dot === name.length - 1) return '';
  return name.slice(dot + 1).toLowerCase();
}

function inspectDownload(download) {
  if (!download || typeof download !== 'object') return { allowed: false, reason: REASON.MISSING_NAME, name: '' };
  const name = typeof download.filename === 'string' ? download.filename : '';
  if (!name.trim()) return { allowed: false, reason: REASON.MISSING_NAME, name: '' };
  if (name.length > MAX_NAME_LENGTH) return { allowed: false, reason: REASON.TOO_LONG, name: '' };
  if (hasControlChars(name)) return { allowed: false, reason: REASON.CONTROL_CHARS, name: '' };
  if (hasBidiOverride(name)) return { allowed: false, reason: REASON.BIDI_OVERRIDE, name: '' };
  if (name.endsWith('.')) return { allowed: false, reason: REASON.TRAILING_DOT, name: '' };
  const ext = extensionOf(name);
  const parts = name.split('.');
  if (parts.length > 2) {
    for (let i = 1; i < parts.length - 1; i += 1) {
      const inner = parts[i].toLowerCase();
      if (DANGEROUS_EXTENSIONS.has(inner)) {
        return { allowed: false, reason: REASON.DOUBLE_EXTENSION, name: '' };
      }
    }
  }
  const documentInner = parts.slice(1, -1).some((part) => DOCUMENT_EXTENSIONS.has(part.toLowerCase()));
  if (documentInner && DANGEROUS_EXTENSIONS.has(ext)) return { allowed: false, reason: REASON.DOUBLE_EXTENSION, name: '' };
  if (DANGEROUS_EXTENSIONS.has(ext)) return { allowed: false, reason: REASON.DANGEROUS_EXTENSION, name: '' };
  if (typeof download.size === 'number' && download.size > MAX_SIZE) {
    return { allowed: false, reason: REASON.TOO_LARGE, name: '' };
  }
  const mime = typeof download.mimeType === 'string' ? download.mimeType.split(';')[0].trim().toLowerCase() : '';
  const expected = MIME_BY_EXTENSION[ext];
  if (mime && expected && mime !== expected && mime !== 'application/octet-stream') {
    return { allowed: false, reason: REASON.MIME_MISMATCH, name: '' };
  }
  if (typeof download.url === 'string') {
    try {
      const parsed = new URL(download.url);
      if (parsed.protocol !== 'https:' && parsed.protocol !== 'blob:' && parsed.protocol !== 'data:') {
        return { allowed: false, reason: REASON.INSECURE_URL, name: '' };
      }
    } catch (err) {
      return { allowed: false, reason: REASON.INSECURE_URL, name: '' };
    }
  }
  return { allowed: true, reason: REASON.OK, name };
}

function applyDownloadPolicyGuard(download) {
  const result = inspectDownload(download);
  return { changed: !result.allowed, reason: result.reason, name: result.name };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.MISSING_NAME:
      return '下载缺少文件名';
    case REASON.CONTROL_CHARS:
      return '下载文件名含控制字符';
    case REASON.BIDI_OVERRIDE:
      return '下载文件名含双向文本覆盖字符';
    case REASON.TRAILING_DOT:
      return '下载文件名以点结尾';
    case REASON.TOO_LONG:
      return '下载文件名超过长度上限';
    case REASON.DANGEROUS_EXTENSION:
      return '下载文件为可执行或脚本类型';
    case REASON.DOUBLE_EXTENSION:
      return '下载文件使用双扩展名伪装';
    case REASON.MIME_MISMATCH:
      return '下载文件扩展名与 MIME 不一致';
    case REASON.TOO_LARGE:
      return '下载文件超过体积上限';
    case REASON.INSECURE_URL:
      return '下载来源不是 HTTPS';
    default:
      return '下载文件通过策略检查';
  }
}

module.exports = {
  REASON,
  MAX_NAME_LENGTH,
  MAX_SIZE,
  DANGEROUS_EXTENSIONS,
  DOCUMENT_EXTENSIONS,
  inspectDownload,
  applyDownloadPolicyGuard,
  describeReason,
};
