'use strict';

const fs = require('fs');
const path = require('path');

const ACTION = { OK: 'ok', WARN: 'warn', BLOCK: 'block' };

const REASON = {
  OK: 'ok',
  UNREADABLE: 'unreadable',
  TOO_SMALL: 'too-small',
  EXECUTABLE_DISGUISE: 'executable-disguise',
  ACTIVE_DISGUISE: 'active-disguise',
  ARCHIVE_MISMATCH: 'archive-mismatch',
  UNKNOWN_TYPE: 'unknown-type',
};

const MAGIC = {
  PE: 'pe',
  ELF: 'elf',
  MACHO: 'macho',
  ZIP: 'zip',
  PDF: 'pdf',
  OLE: 'ole',
  HTML: 'html',
  SCRIPT: 'script',
  RTF: 'rtf',
  PNG: 'png',
  JPEG: 'jpeg',
  GIF: 'gif',
  SEVEN_ZIP: '7z',
  RAR: 'rar',
  UNKNOWN: 'unknown',
};

const IMAGE_EXTS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.ico']);
const EXECUTABLE_EXTS = new Set(['.exe', '.scr', '.com', '.dll', '.sys', '.msi', '.bat', '.cmd', '.ps1', '.sh', '.jar']);
const ARCHIVE_EXTS = new Set(['.zip', '.7z', '.rar', '.gz', '.tar', '.docx', '.xlsx', '.pptx', '.apk', '.jar']);
const DOC_EXTS = new Set(['.pdf', '.rtf', '.doc', '.xls', '.ppt']);

function extOf(name) {
  return path.extname(String(name || '')).toLowerCase();
}

function sniffBuffer(buffer) {
  if (!buffer || buffer.length === 0) return MAGIC.UNKNOWN;
  const head = buffer.subarray(0, Math.min(buffer.length, 512));
  const text = head.toString('utf8').trimStart().toLowerCase();
  if (head.length >= 2 && head[0] === 0x4d && head[1] === 0x5a) return MAGIC.PE;
  if (head.length >= 4 && head.readUInt32BE(0) === 0x7f454c46) return MAGIC.ELF;
  if (head.length >= 4) {
    const be = head.readUInt32BE(0);
    if (be === 0xcafebabe || be === 0xfeedface || be === 0xfeedfacf || be === 0xcefaedfe) return MAGIC.MACHO;
  }
  if (head.length >= 4 && head.readUInt32BE(0) === 0x504b0304) return MAGIC.ZIP;
  if (text.startsWith('%pdf-')) return MAGIC.PDF;
  if (head.length >= 8 && head.readUInt32BE(0) === 0xd0cf11e0) return MAGIC.OLE;
  if (text.startsWith('<!doctype html') || text.startsWith('<html') || text.startsWith('<head') || text.startsWith('<body')) {
    return MAGIC.HTML;
  }
  if (text.startsWith('<script') || text.startsWith('<?php') || text.startsWith('#!/')) return MAGIC.SCRIPT;
  if (text.startsWith('{\\rtf')) return MAGIC.RTF;
  if (head.length >= 8 && head.readUInt32BE(0) === 0x89504e47) return MAGIC.PNG;
  if (head.length >= 3 && head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff) return MAGIC.JPEG;
  if (text.startsWith('gif87a') || text.startsWith('gif89a')) return MAGIC.GIF;
  if (head.length >= 6 && head.subarray(0, 6).toString('hex') === '377abcaf271c') return MAGIC.SEVEN_ZIP;
  if (head.length >= 7 && head.subarray(0, 7).toString('hex') === '526172211a0700') return MAGIC.RAR;
  return MAGIC.UNKNOWN;
}

function readMagic(filePath, options = {}) {
  const readBytes = Number.isFinite(options.readBytes) && options.readBytes > 0 ? options.readBytes : 512;
  let fd = null;
  try {
    fd = fs.openSync(String(filePath || ''), 'r');
    const buffer = Buffer.alloc(readBytes);
    const read = fs.readSync(fd, buffer, 0, readBytes, 0);
    if (read <= 0) return { ok: false, magic: MAGIC.UNKNOWN, reason: REASON.TOO_SMALL };
    return { ok: true, magic: sniffBuffer(buffer.subarray(0, read)), reason: REASON.OK };
  } catch {
    return { ok: false, magic: MAGIC.UNKNOWN, reason: REASON.UNREADABLE };
  } finally {
    if (fd !== null) {
      try { fs.closeSync(fd); } catch {}
    }
  }
}

function auditDownloadedContent(input = {}) {
  const name = String(input.name || '');
  const mime = String(input.mime || '').toLowerCase();
  const magic = String(input.magic || MAGIC.UNKNOWN);
  const ext = extOf(name);
  const base = { action: ACTION.OK, reason: REASON.OK, detail: '', ext, magic };

  if (magic === MAGIC.UNKNOWN) {
    return Object.assign(base, { action: ACTION.WARN, reason: REASON.UNKNOWN_TYPE, detail: '文件头无法识别，可能是纯文本或未知格式' });
  }
  const executableMagic = magic === MAGIC.PE || magic === MAGIC.ELF || magic === MAGIC.MACHO;
  if (executableMagic && !EXECUTABLE_EXTS.has(ext)) {
    return Object.assign(base, {
      action: ACTION.BLOCK, reason: REASON.EXECUTABLE_DISGUISE,
      detail: `扩展名 ${ext || '(无)'} 声明为普通文件，实际是可执行文件头 ${magic}`,
    });
  }
  if ((magic === MAGIC.HTML || magic === MAGIC.SCRIPT) && (IMAGE_EXTS.has(ext) || DOC_EXTS.has(ext))) {
    return Object.assign(base, {
      action: ACTION.BLOCK, reason: REASON.ACTIVE_DISGUISE,
      detail: `扩展名 ${ext} 声明为图片/文档，实际是 HTML/脚本内容`,
    });
  }
  if (mime.startsWith('image/') && (magic === MAGIC.HTML || magic === MAGIC.SCRIPT || executableMagic)) {
    return Object.assign(base, {
      action: ACTION.BLOCK, reason: REASON.ACTIVE_DISGUISE,
      detail: `响应声明 ${mime}，实际内容为 ${magic}`,
    });
  }
  if (ARCHIVE_EXTS.has(ext) && magic !== MAGIC.ZIP && magic !== MAGIC.SEVEN_ZIP && magic !== MAGIC.RAR) {
    return Object.assign(base, {
      action: ACTION.WARN, reason: REASON.ARCHIVE_MISMATCH,
      detail: `扩展名 ${ext} 但文件头不是已知压缩格式 (${magic})`,
    });
  }
  return base;
}

function describeContentAudit(audit) {
  if (!audit || audit.reason === REASON.OK) return '下载内容类型校验通过';
  return `${audit.reason}: ${audit.detail || ''}`.trim();
}

module.exports = {
  ACTION,
  REASON,
  MAGIC,
  sniffBuffer,
  readMagic,
  auditDownloadedContent,
  describeContentAudit,
};
