'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'empty',
  NOT_LIST: 'not-list',
  TOO_MANY_ENTRIES: 'too-many-entries',
  TOO_LONG_NAME: 'too-long-name',
  ABSOLUTE: 'absolute-entry',
  DRIVE: 'drive-letter-entry',
  TRAVERSAL: 'traversal-entry',
  BACKSLASH: 'backslash-entry',
  CONTROL: 'control-characters',
  DUPLICATE: 'duplicate-entry',
  BOMB_RATIO: 'compression-bomb',
};

const MAX_ENTRIES = 10000;
const MAX_NAME = 1024;
const MAX_RATIO = 200;

function hasControlChars(value) {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

function inspectEntryName(name) {
  if (typeof name !== 'string' || !name) return { ok: false, reason: REASON.EMPTY };
  if (name.length > MAX_NAME) return { ok: false, reason: REASON.TOO_LONG_NAME };
  if (hasControlChars(name)) return { ok: false, reason: REASON.CONTROL };
  if (name.includes('\\')) return { ok: false, reason: REASON.BACKSLASH };
  if (name.startsWith('/')) return { ok: false, reason: REASON.ABSOLUTE };
  if (/^[a-zA-Z]:/.test(name)) return { ok: false, reason: REASON.DRIVE };
  const segments = name.split('/');
  for (const segment of segments) {
    if (segment === '..') return { ok: false, reason: REASON.TRAVERSAL };
  }
  return { ok: true, reason: REASON.OK };
}

function inspectArchive(entries, meta) {
  if (!Array.isArray(entries)) return { ok: false, reason: REASON.NOT_LIST };
  if (entries.length === 0) return { ok: false, reason: REASON.EMPTY };
  if (entries.length > MAX_ENTRIES) return { ok: false, reason: REASON.TOO_MANY_ENTRIES };
  const seen = new Set();
  for (const entry of entries) {
    const result = inspectEntryName(entry);
    if (!result.ok) return { ok: false, reason: result.reason, entry };
    const key = entry.toLowerCase();
    if (seen.has(key)) return { ok: false, reason: REASON.DUPLICATE, entry };
    seen.add(key);
  }
  if (meta && typeof meta === 'object') {
    const compressed = Number(meta.compressedSize);
    const uncompressed = Number(meta.uncompressedSize);
    if (Number.isFinite(compressed) && compressed > 0 && Number.isFinite(uncompressed)) {
      if (uncompressed / compressed > MAX_RATIO) return { ok: false, reason: REASON.BOMB_RATIO };
    }
  }
  return { ok: true, reason: REASON.OK, count: entries.length };
}

function applyArchiveEntryGuard(entries, meta) {
  const result = inspectArchive(entries, meta);
  return { changed: !result.ok, reason: result.reason, count: result.count || 0 };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.EMPTY:
      return '压缩包为空或条目名为空';
    case REASON.NOT_LIST:
      return '压缩包条目不是列表';
    case REASON.TOO_MANY_ENTRIES:
      return '压缩包条目数量过多';
    case REASON.TOO_LONG_NAME:
      return '压缩包条目名过长';
    case REASON.ABSOLUTE:
      return '压缩包条目使用绝对路径';
    case REASON.DRIVE:
      return '压缩包条目带盘符';
    case REASON.TRAVERSAL:
      return '压缩包条目包含上级目录片段';
    case REASON.BACKSLASH:
      return '压缩包条目使用反斜杠分隔';
    case REASON.CONTROL:
      return '压缩包条目名含控制字符';
    case REASON.DUPLICATE:
      return '压缩包存在重复条目';
    case REASON.BOMB_RATIO:
      return '压缩包压缩比异常疑似压缩炸弹';
    default:
      return '压缩包条目结构安全';
  }
}

module.exports = {
  REASON,
  MAX_ENTRIES,
  MAX_NAME,
  MAX_RATIO,
  inspectEntryName,
  inspectArchive,
  applyArchiveEntryGuard,
  describeReason,
};
