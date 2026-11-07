'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'empty',
  TOO_SHORT: 'too-short',
  EXECUTABLE_MISMATCH: 'executable-mismatch',
  TYPE_MISMATCH: 'type-mismatch',
  UNKNOWN: 'unknown-type',
};

const KIND = {
  PE: 'pe',
  ELF: 'elf',
  MACHO: 'macho',
  JAVA: 'java-class',
  ZIP: 'zip',
  OLE: 'ole',
  PDF: 'pdf',
  PNG: 'png',
  JPEG: 'jpeg',
  GIF: 'gif',
  WEBP: 'webp',
  SCRIPT: 'script',
  UNKNOWN: 'unknown',
};

const EXECUTABLE_KINDS = new Set([KIND.PE, KIND.ELF, KIND.MACHO, KIND.JAVA, KIND.SCRIPT]);
const IMAGE_KINDS = new Set([KIND.PNG, KIND.JPEG, KIND.GIF, KIND.WEBP]);

function startsWith(buffer, bytes, offset) {
  if (buffer.length < offset + bytes.length) return false;
  for (let i = 0; i < bytes.length; i += 1) {
    if (buffer[offset + i] !== bytes[i]) return false;
  }
  return true;
}

function detectKind(buffer) {
  if (startsWith(buffer, Buffer.from([0x4d, 0x5a]), 0)) return KIND.PE;
  if (startsWith(buffer, Buffer.from([0x7f, 0x45, 0x4c, 0x46]), 0)) return KIND.ELF;
  if (startsWith(buffer, Buffer.from([0xca, 0xfe, 0xba, 0xbe]), 0)) return KIND.JAVA;
  if (startsWith(buffer, Buffer.from([0xfe, 0xed, 0xfa, 0xce]), 0)) return KIND.MACHO;
  if (startsWith(buffer, Buffer.from([0xce, 0xfa, 0xed, 0xfe]), 0)) return KIND.MACHO;
  if (startsWith(buffer, Buffer.from([0xcf, 0xfa, 0xed, 0xfe]), 0)) return KIND.MACHO;
  if (startsWith(buffer, Buffer.from([0x50, 0x4b, 0x03, 0x04]), 0)) return KIND.ZIP;
  if (startsWith(buffer, Buffer.from([0xd0, 0xcf, 0x11, 0xe0]), 0)) return KIND.OLE;
  if (startsWith(buffer, Buffer.from('%PDF-', 'ascii'), 0)) return KIND.PDF;
  if (startsWith(buffer, Buffer.from([0x89, 0x50, 0x4e, 0x47]), 0)) return KIND.PNG;
  if (startsWith(buffer, Buffer.from([0xff, 0xd8, 0xff]), 0)) return KIND.JPEG;
  if (startsWith(buffer, Buffer.from('GIF87a', 'ascii'), 0) || startsWith(buffer, Buffer.from('GIF89a', 'ascii'), 0)) return KIND.GIF;
  if (startsWith(buffer, Buffer.from('RIFF', 'ascii'), 0) && startsWith(buffer, Buffer.from('WEBP', 'ascii'), 8)) return KIND.WEBP;
  if (startsWith(buffer, Buffer.from('#!', 'ascii'), 0)) return KIND.SCRIPT;
  return KIND.UNKNOWN;
}

function normalizeDeclared(declaredType) {
  if (typeof declaredType !== 'string') return '';
  return declaredType.split(';')[0].trim().toLowerCase();
}

function expectedKinds(declaredType) {
  switch (normalizeDeclared(declaredType)) {
    case 'image/png':
      return [KIND.PNG];
    case 'image/jpeg':
      return [KIND.JPEG];
    case 'image/gif':
      return [KIND.GIF];
    case 'image/webp':
      return [KIND.WEBP];
    case 'application/pdf':
      return [KIND.PDF];
    case 'application/zip':
      return [KIND.ZIP];
    default:
      return [];
  }
}

function inspectMagic(buffer, declaredType) {
  if (!Buffer.isBuffer(buffer)) return { kind: KIND.UNKNOWN, executable: false, reason: REASON.EMPTY };
  if (buffer.length === 0) return { kind: KIND.UNKNOWN, executable: false, reason: REASON.EMPTY };
  if (buffer.length < 4) return { kind: KIND.UNKNOWN, executable: false, reason: REASON.TOO_SHORT };
  const kind = detectKind(buffer);
  const executable = EXECUTABLE_KINDS.has(kind);
  const expected = expectedKinds(declaredType);
  if (expected.length) {
    if (expected.includes(KIND.PNG) || expected.includes(KIND.JPEG) || expected.includes(KIND.GIF) || expected.includes(KIND.WEBP)) {
      if (executable) return { kind, executable, reason: REASON.EXECUTABLE_MISMATCH };
    }
    if (!expected.includes(kind)) return { kind, executable, reason: REASON.TYPE_MISMATCH };
  }
  if (kind === KIND.UNKNOWN) return { kind, executable: false, reason: REASON.UNKNOWN };
  return { kind, executable, reason: REASON.OK };
}

function applyFileMagicGuard(buffer, declaredType) {
  const result = inspectMagic(buffer, declaredType);
  const allowed = result.reason === REASON.OK && !result.executable;
  return { changed: !allowed, reason: result.reason, kind: result.kind, executable: result.executable };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.EMPTY:
      return '文件内容为空';
    case REASON.TOO_SHORT:
      return '文件长度不足以识别类型';
    case REASON.EXECUTABLE_MISMATCH:
      return '声明为图片但内容是可执行文件';
    case REASON.TYPE_MISMATCH:
      return '文件内容与声明的类型不一致';
    case REASON.UNKNOWN:
      return '无法识别文件类型';
    default:
      return '文件类型与内容一致';
  }
}

module.exports = {
  REASON,
  KIND,
  EXECUTABLE_KINDS,
  IMAGE_KINDS,
  detectKind,
  inspectMagic,
  applyFileMagicGuard,
  describeReason,
};
