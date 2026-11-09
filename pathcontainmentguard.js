'use strict';
const { describeReasonFrom } = require('./reasontext');

const REASON = {
  OK: 'ok',
  EMPTY: 'empty',
  CONTROL: 'control-characters',
  TOO_LONG: 'too-long',
  ABSOLUTE: 'absolute-path',
  UNC: 'unc-path',
  TRAVERSAL: 'traversal',
  ENCODED_TRAVERSAL: 'encoded-traversal',
  DRIVE_RELATIVE: 'drive-relative',
  ALT_STREAM: 'alt-stream',
  OUTSIDE: 'outside-base',
};

const MAX_PATH_LENGTH = 4096;

function hasControlChars(value) {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code === 0) return true;
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

function decodeOnce(value) {
  return value.replace(/%([0-9a-fA-F]{2})/g, (all, hex) => String.fromCharCode(parseInt(hex, 16)));
}

function looksEncodedSeparator(value) {
  if (!/%[0-9a-fA-F]{2}/.test(value)) return false;
  const decoded = decodeOnce(value).replace(/\\/g, '/').toLowerCase();
  if (decoded.includes('..')) return true;
  if (decoded.includes(':/') || decoded.startsWith('/')) return true;
  return false;
}

function looksEncodedTraversal(value) {
  const lower = value.toLowerCase();
  return lower.includes('%2e%2e') || lower.includes('%2f%2e') || lower.includes('%00') || lower.includes('%252e');
}

function inspectPath(baseDir, target) {
  if (typeof baseDir !== 'string' || typeof target !== 'string') return { ok: false, reason: REASON.EMPTY, resolved: '' };
  const base = baseDir.replace(/\\/g, '/').replace(/\/+$/, '');
  const input = target.replace(/\\/g, '/');
  if (!input.trim()) return { ok: false, reason: REASON.EMPTY, resolved: '' };
  if (input.length > MAX_PATH_LENGTH) return { ok: false, reason: REASON.TOO_LONG, resolved: '' };
  if (hasControlChars(input)) return { ok: false, reason: REASON.CONTROL, resolved: '' };
  if (looksEncodedTraversal(input)) return { ok: false, reason: REASON.ENCODED_TRAVERSAL, resolved: '' };
  if (input.startsWith('//')) return { ok: false, reason: REASON.UNC, resolved: '' };
  if (input.startsWith('/') || /^[a-zA-Z]:\//.test(input)) return { ok: false, reason: REASON.ABSOLUTE, resolved: '' };
  if (/^[a-zA-Z]:[^/]/.test(input)) return { ok: false, reason: REASON.DRIVE_RELATIVE, resolved: '' };
  if (looksEncodedSeparator(input)) return { ok: false, reason: REASON.ENCODED_TRAVERSAL, resolved: '' };
  const segments = input.split('/');
  const cleaned = [];
  for (const segment of segments) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') return { ok: false, reason: REASON.TRAVERSAL, resolved: '' };
    if (segment.includes(':')) return { ok: false, reason: REASON.ALT_STREAM, resolved: '' };
    cleaned.push(segment);
  }
  if (!base) return { ok: false, reason: REASON.EMPTY, resolved: '' };
  const resolved = cleaned.length ? base + '/' + cleaned.join('/') : base;
  const lowerResolved = resolved.toLowerCase();
  const lowerBase = base.toLowerCase();
  if (lowerResolved !== lowerBase && !lowerResolved.startsWith(lowerBase + '/')) {
    return { ok: false, reason: REASON.OUTSIDE, resolved: '' };
  }
  return { ok: true, reason: REASON.OK, resolved };
}

function applyPathContainmentGuard(baseDir, target) {
  const result = inspectPath(baseDir, target);
  return { changed: !result.ok, reason: result.reason, resolved: result.resolved };
}

function describeReason(reason) {
  return describeReasonFrom({
    [REASON.EMPTY]: '路径为空或不是字符串',
    [REASON.CONTROL]: '路径包含控制字符',
    [REASON.TOO_LONG]: '路径超过长度上限',
    [REASON.ABSOLUTE]: '路径为绝对路径',
    [REASON.UNC]: '路径为 UNC 网络路径',
    [REASON.TRAVERSAL]: '路径包含上级目录片段',
    [REASON.ENCODED_TRAVERSAL]: '路径包含编码后的上级目录片段',
    [REASON.DRIVE_RELATIVE]: '路径为未带分隔符的盘符相对路径',
    [REASON.ALT_STREAM]: '路径包含 NTFS 备用数据流分隔符',
    [REASON.OUTSIDE]: '路径解析后落在根目录之外',
  }, reason, '路径位于允许的根目录之内');
}

module.exports = {
  REASON,
  MAX_PATH_LENGTH,
  inspectPath,
  applyPathContainmentGuard,
  describeReason,
};
