const { describeReasonFrom } = require('./reasontext');
const path = require('path');
const { safeInt, isPlainObject } = require('./modutil_core');

const DEFAULT_MAX_ENTRIES = 200;
const DEFAULT_MAX_FILE_BYTES = 256 * 1024;
const DEFAULT_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_URL_CHARS = 8192;
const MAX_FILENAME_CHARS = 180;
const MAX_PATH_CHARS = 4096;
const MAX_ID_CHARS = 64;

const STATE = {
  STARTED: 'started',
  DOWNLOADING: 'downloading',
  COMPLETE: 'complete',
  INTERRUPTED: 'interrupted',
  ERROR: 'error',
};

const VALID_STATES = new Set(Object.values(STATE));

const REASON = {
  OK: 'ok',
  BAD_SHAPE: 'bad-shape',
  BAD_ID: 'bad-id',
  BAD_URL: 'bad-url',
  BAD_FILENAME: 'bad-filename',
  BAD_STATE: 'bad-state',
  BAD_PATH: 'bad-path',
  BAD_BYTES: 'bad-bytes',
  BAD_TIME: 'bad-time',
  TOO_MANY: 'too-many',
  TOO_LARGE: 'too-large',
  IO_ERROR: 'io-error',
};

const JOURNAL_REJECT_TEXT = {
  [REASON.OK]: '记录合法',
  [REASON.BAD_SHAPE]: '下载记录结构非法',
  [REASON.BAD_ID]: '下载记录 ID 非法',
  [REASON.BAD_URL]: '下载记录地址非法',
  [REASON.BAD_FILENAME]: '下载记录文件名非法',
  [REASON.BAD_STATE]: '下载记录状态非法',
  [REASON.BAD_PATH]: '下载记录路径越界',
  [REASON.BAD_BYTES]: '下载记录字节数非法',
  [REASON.BAD_TIME]: '下载记录时间戳非法',
  [REASON.TOO_MANY]: '下载记录条数超限',
  [REASON.TOO_LARGE]: '下载记录文件超大',
  [REASON.IO_ERROR]: '下载记录读写失败',
};

function describeJournalReject(reason) {
  return describeReasonFrom(JOURNAL_REJECT_TEXT, reason, '未知下载记录问题');
}

function cleanId(value) {
  if (typeof value !== 'string') return '';
  const id = value.trim();
  if (id.length === 0 || id.length > MAX_ID_CHARS) return '';
  if (!/^[A-Za-z0-9_-]+$/.test(id)) return '';
  return id;
}

function cleanFilename(value) {
  if (typeof value !== 'string') return '';
  const name = value.trim();
  if (name.length === 0 || name.length > MAX_FILENAME_CHARS) return '';
  if (/[\u0000-\u001f\u007f/\\]/.test(name)) return '';
  if (name === '.' || name === '..') return '';
  return name;
}

function cleanURL(value) {
  if (typeof value !== 'string') return '';
  const url = value.trim();
  if (url.length === 0 || url.length > MAX_URL_CHARS) return '';
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return '';
  }
  if (parsed.protocol !== 'https:') return '';
  if (parsed.username || parsed.password) return '';
  return url;
}

function cleanPathWithin(rootDir, value) {
  if (typeof value !== 'string') return '';
  const target = value.trim();
  if (target.length === 0 || target.length > MAX_PATH_CHARS) return '';
  if (!rootDir) return target;
  const rel = path.relative(rootDir, target);
  if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) return '';
  return target;
}

function normalizeEntry(entry, rootDir, now) {
  const reject = (reason) => ({ ok: false, reason });
  if (!isPlainObject(entry)) return reject(REASON.BAD_SHAPE);
  const id = cleanId(entry.id);
  if (!id) return reject(REASON.BAD_ID);
  const url = cleanURL(entry.url);
  if (!url) return reject(REASON.BAD_URL);
  const filename = cleanFilename(entry.filename);
  if (!filename) return reject(REASON.BAD_FILENAME);
  const state = typeof entry.state === 'string' ? entry.state : '';
  if (!VALID_STATES.has(state)) return reject(REASON.BAD_STATE);
  const totalBytes = safeInt(entry.totalBytes);
  const receivedBytes = safeInt(entry.receivedBytes);
  if (totalBytes === null || receivedBytes === null) return reject(REASON.BAD_BYTES);
  if (receivedBytes > totalBytes) return reject(REASON.BAD_BYTES);
  const startedAt = safeInt(entry.startedAt);
  if (startedAt === null || startedAt > now) return reject(REASON.BAD_TIME);
  const updatedAt = safeInt(entry.updatedAt) ?? startedAt;
  if (updatedAt > now) return reject(REASON.BAD_TIME);
  let savePath = '';
  if (entry.savePath) {
    savePath = cleanPathWithin(rootDir, entry.savePath);
    if (!savePath) return reject(REASON.BAD_PATH);
  }
  let partPath = '';
  if (entry.partPath) {
    partPath = cleanPathWithin(rootDir, entry.partPath);
    if (!partPath) return reject(REASON.BAD_PATH);
  }
  let host = '';
  if (typeof entry.host === 'string') {
    host = entry.host.trim().toLowerCase();
  }
  return {
    ok: true,
    entry: {
      id,
      url,
      filename,
      host: host.slice(0, 253),
      savePath,
      partPath,
      totalBytes,
      receivedBytes,
      state,
      startedAt,
      updatedAt,
    },
  };
}

module.exports = {
  DEFAULT_MAX_ENTRIES,
  DEFAULT_MAX_FILE_BYTES,
  DEFAULT_RETENTION_MS,
  MAX_URL_CHARS,
  MAX_FILENAME_CHARS,
  MAX_PATH_CHARS,
  MAX_ID_CHARS,
  STATE,
  VALID_STATES,
  REASON,
  describeJournalReject,
  cleanId,
  cleanFilename,
  cleanURL,
  cleanPathWithin,
  normalizeEntry,
};
