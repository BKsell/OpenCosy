'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'empty',
  CONTROL: 'control-characters',
  TOO_LONG: 'too-long',
  ABSOLUTE: 'absolute-path',
  UNC: 'unc-path',
  TRAVERSAL: 'traversal',
  ENCODED_TRAVERSAL: 'encoded-traversal',
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
  const segments = input.split('/');
  const cleaned = [];
  for (const segment of segments) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') return { ok: false, reason: REASON.TRAVERSAL, resolved: '' };
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
  switch (reason) {
    case REASON.EMPTY:
      return '路径为空或不是字符串';
    case REASON.CONTROL:
      return '路径包含控制字符';
    case REASON.TOO_LONG:
      return '路径超过长度上限';
    case REASON.ABSOLUTE:
      return '路径为绝对路径';
    case REASON.UNC:
      return '路径为 UNC 网络路径';
    case REASON.TRAVERSAL:
      return '路径包含上级目录片段';
    case REASON.ENCODED_TRAVERSAL:
      return '路径包含编码后的上级目录片段';
    case REASON.OUTSIDE:
      return '路径解析后落在根目录之外';
    default:
      return '路径位于允许的根目录之内';
  }
}

module.exports = {
  REASON,
  MAX_PATH_LENGTH,
  inspectPath,
  applyPathContainmentGuard,
  describeReason,
};
