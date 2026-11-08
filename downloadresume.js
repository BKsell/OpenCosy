'use strict';

const path = require('path');

const DEFAULT_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const DEFAULT_MAX_TOTAL_BYTES = 8 * 1024 * 1024 * 1024;
const MAX_URL_CHARS = 8192;
const MAX_HOST_CHARS = 253;

const REASON = {
  OK: 'ok',
  BAD_SHAPE: 'bad-shape',
  BAD_URL: 'bad-url',
  BAD_SCHEME: 'bad-scheme',
  BAD_HOST: 'bad-host',
  BAD_PATH: 'bad-path',
  PART_MISSING: 'part-missing',
  SIZE_MISMATCH: 'size-mismatch',
  STALE: 'stale',
  BAD_BYTES: 'bad-bytes',
  TOO_LARGE: 'too-large',
};

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function safeNonNegativeInt(value) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return null;
  if (!Number.isInteger(value)) return null;
  return value;
}

function normalizeHost(value) {
  if (typeof value !== 'string') return '';
  const host = value.trim().toLowerCase();
  if (host.length === 0 || host.length > MAX_HOST_CHARS) return '';
  if (/[\s/\\@]/.test(host)) return '';
  return host;
}

function describeResumeReject(reason) {
  switch (reason) {
    case REASON.OK: return '可以续传';
    case REASON.BAD_SHAPE: return '续传记录结构非法';
    case REASON.BAD_URL: return '续传地址非法';
    case REASON.BAD_SCHEME: return '续传地址不是 HTTPS';
    case REASON.BAD_HOST: return '续传目标主机与原始主机不一致';
    case REASON.BAD_PATH: return '续传临时文件路径越界';
    case REASON.PART_MISSING: return '续传临时文件不存在';
    case REASON.SIZE_MISMATCH: return '续传临时文件大小与记录不一致';
    case REASON.STALE: return '续传记录已过期';
    case REASON.BAD_BYTES: return '续传字节计数非法';
    case REASON.TOO_LARGE: return '续传体积超过上限';
    default: return '未知续传问题';
  }
}

function auditResumeCandidate(entry, options = {}) {
  const opts = isPlainObject(options) ? options : {};
  const now = safeNonNegativeInt(opts.now) ?? Date.now();
  const maxAgeMs = safeNonNegativeInt(opts.maxAgeMs) ?? DEFAULT_MAX_AGE_MS;
  const maxTotalBytes = safeNonNegativeInt(opts.maxTotalBytes) ?? DEFAULT_MAX_TOTAL_BYTES;
  const rootDir = typeof opts.rootDir === 'string' && opts.rootDir.length > 0 ? opts.rootDir : '';
  const exists = typeof opts.exists === 'function' ? opts.exists : null;
  const sizeOf = typeof opts.sizeOf === 'function' ? opts.sizeOf : null;
  const verdict = (reason, extra = {}) => ({ resumable: reason === REASON.OK, reason, offset: 0, ...extra });
  if (!isPlainObject(entry)) return verdict(REASON.BAD_SHAPE);
  const url = typeof entry.url === 'string' ? entry.url : '';
  if (url.length === 0 || url.length > MAX_URL_CHARS) return verdict(REASON.BAD_URL);
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return verdict(REASON.BAD_URL);
  }
  if (parsed.protocol !== 'https:') return verdict(REASON.BAD_SCHEME);
  if (parsed.username || parsed.password) return verdict(REASON.BAD_URL);
  const host = normalizeHost(entry.host || parsed.hostname);
  if (!host) return verdict(REASON.BAD_HOST);
  if (host !== normalizeHost(parsed.hostname)) return verdict(REASON.BAD_HOST);
  const partPath = typeof entry.partPath === 'string' ? entry.partPath : '';
  if (partPath.length === 0 || partPath.length > 4096) return verdict(REASON.BAD_PATH);
  if (rootDir) {
    const rel = path.relative(rootDir, partPath);
    if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) {
      return verdict(REASON.BAD_PATH);
    }
  }
  if (exists && exists(partPath) !== true) return verdict(REASON.PART_MISSING);
  const receivedBytes = safeNonNegativeInt(entry.receivedBytes);
  const totalBytes = safeNonNegativeInt(entry.totalBytes);
  if (receivedBytes === null || totalBytes === null) return verdict(REASON.BAD_BYTES);
  if (totalBytes > maxTotalBytes) return verdict(REASON.TOO_LARGE);
  if (receivedBytes > totalBytes) return verdict(REASON.BAD_BYTES);
  if (receivedBytes === 0) return verdict(REASON.PART_MISSING);
  const startedAt = safeNonNegativeInt(entry.startedAt);
  if (startedAt === null || startedAt > now) return verdict(REASON.BAD_BYTES);
  if (now - startedAt > maxAgeMs) return verdict(REASON.STALE);
  if (sizeOf) {
    let actual = null;
    try {
      actual = sizeOf(partPath);
    } catch {
      actual = null;
    }
    if (safeNonNegativeInt(actual) === null) return verdict(REASON.PART_MISSING);
    if (actual !== receivedBytes) return verdict(REASON.SIZE_MISMATCH);
  }
  return verdict(REASON.OK, { offset: receivedBytes });
}

module.exports = {
  REASON,
  DEFAULT_MAX_AGE_MS,
  DEFAULT_MAX_TOTAL_BYTES,
  MAX_URL_CHARS,
  auditResumeCandidate,
  describeResumeReject,
};
