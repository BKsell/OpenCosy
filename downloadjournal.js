'use strict';

const fs = require('fs');
const path = require('path');
const downloadResume = require('./downloadresume');

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

function describeJournalReject(reason) {
  switch (reason) {
    case REASON.OK: return '记录合法';
    case REASON.BAD_SHAPE: return '下载记录结构非法';
    case REASON.BAD_ID: return '下载记录 ID 非法';
    case REASON.BAD_URL: return '下载记录地址非法';
    case REASON.BAD_FILENAME: return '下载记录文件名非法';
    case REASON.BAD_STATE: return '下载记录状态非法';
    case REASON.BAD_PATH: return '下载记录路径越界';
    case REASON.BAD_BYTES: return '下载记录字节数非法';
    case REASON.BAD_TIME: return '下载记录时间戳非法';
    case REASON.TOO_MANY: return '下载记录条数超限';
    case REASON.TOO_LARGE: return '下载记录文件超大';
    case REASON.IO_ERROR: return '下载记录读写失败';
    default: return '未知下载记录问题';
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function safeInt(value) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return null;
  if (!Number.isInteger(value)) return null;
  return value;
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

function createDownloadJournal(options = {}) {
  const opts = isPlainObject(options) ? options : {};
  const filePath = typeof opts.filePath === 'string' ? opts.filePath : '';
  const rootDir = typeof opts.rootDir === 'string' ? opts.rootDir : '';
  const maxEntries = safeInt(opts.maxEntries) ?? DEFAULT_MAX_ENTRIES;
  const maxFileBytes = safeInt(opts.maxFileBytes) ?? DEFAULT_MAX_FILE_BYTES;
  const retentionMs = safeInt(opts.retentionMs) ?? DEFAULT_RETENTION_MS;
  const clock = typeof opts.now === 'function' ? opts.now : () => Date.now();
  const fsImpl = isPlainObject(opts.fsImpl) ? opts.fsImpl : fs;
  if (!filePath) throw new Error('download journal file path is required');

  let entries = [];
  let lastRejected = [];
  let tmpSeq = 0;

  function partStats(target) {
    try {
      const stat = fsImpl.statSync(target);
      if (!stat.isFile()) return null;
      return stat.size;
    } catch {
      return null;
    }
  }

  function applyResumeVerdict(entry, now) {
    entry.resumable = false;
    entry.resumeReason = downloadResume.REASON.OK;
    entry.resumeOffset = 0;
    if (entry.state !== STATE.INTERRUPTED) return;
    const resume = downloadResume.auditResumeCandidate(
      { ...entry, partPath: entry.partPath || entry.savePath },
      { rootDir, now, exists: (p) => partStats(p) !== null, sizeOf: (p) => partStats(p) },
    );
    entry.resumable = resume.resumable;
    entry.resumeReason = resume.reason;
    entry.resumeOffset = resume.offset;
  }

  function prune(list, now) {
    const kept = [];
    for (const entry of list) {
      const age = now - entry.startedAt;
      if (age > retentionMs) continue;
      kept.push(entry);
    }
    return kept.slice(0, maxEntries);
  }

  function load() {
    const now = clock();
    const rejected = [];
    entries = [];
    if (!fsImpl.existsSync(filePath)) {
      lastRejected = [];
      return { entries: [], rejected: [] };
    }
    let text = '';
    try {
      const stat = fsImpl.statSync(filePath);
      if (stat.size > maxFileBytes) {
        lastRejected = [REASON.TOO_LARGE];
        return { entries: [], rejected: [REASON.TOO_LARGE] };
      }
      text = fsImpl.readFileSync(filePath, 'utf8');
    } catch {
      lastRejected = [REASON.IO_ERROR];
      return { entries: [], rejected: [REASON.IO_ERROR] };
    }
    let payload;
    try {
      payload = JSON.parse(text);
    } catch {
      lastRejected = [REASON.BAD_SHAPE];
      return { entries: [], rejected: [REASON.BAD_SHAPE] };
    }
    const rawEntries = Array.isArray(payload) ? payload : (isPlainObject(payload) && Array.isArray(payload.entries) ? payload.entries : null);
    if (!rawEntries) {
      lastRejected = [REASON.BAD_SHAPE];
      return { entries: [], rejected: [REASON.BAD_SHAPE] };
    }
    const seen = new Set();
    for (const raw of rawEntries) {
      const result = normalizeEntry(raw, rootDir, now);
      if (!result.ok) {
        rejected.push(result.reason);
        continue;
      }
      if (seen.has(result.entry.id)) {
        rejected.push(REASON.BAD_ID);
        continue;
      }
      seen.add(result.entry.id);
      applyResumeVerdict(result.entry, now);
      entries.push(result.entry);
    }
    entries = prune(entries, now);
    lastRejected = rejected;
    return { entries: entries.slice(), rejected: rejected.slice() };
  }

  function save() {
    const now = clock();
    const payload = JSON.stringify({ version: 1, updatedAt: now, entries }, null, 2);
    if (Buffer.byteLength(payload, 'utf8') > maxFileBytes) {
      lastRejected.push(REASON.TOO_LARGE);
      return { ok: false, reason: REASON.TOO_LARGE };
    }
    const dir = path.dirname(filePath);
    const tmp = path.join(dir, `.download-journal-${process.pid}-${now}-${tmpSeq++}.tmp`);
    try {
      fsImpl.mkdirSync(dir, { recursive: true, mode: 0o700 });
      fsImpl.writeFileSync(tmp, payload, { encoding: 'utf8', mode: 0o600 });
      fsImpl.renameSync(tmp, filePath);
      return { ok: true, reason: REASON.OK };
    } catch {
      try { fsImpl.unlinkSync(tmp); } catch {}
      lastRejected.push(REASON.IO_ERROR);
      return { ok: false, reason: REASON.IO_ERROR };
    }
  }

  function record(entry) {
    const now = clock();
    const result = normalizeEntry({ ...entry, updatedAt: entry.updatedAt ?? now }, rootDir, now);
    if (!result.ok) return { ok: false, reason: result.reason };
    const next = { ...result.entry, resumable: false, resumeReason: downloadResume.REASON.OK, resumeOffset: 0 };
    applyResumeVerdict(next, now);
    entries = entries.filter((item) => item.id !== next.id);
    entries.unshift(next);
    entries = prune(entries, now);
    const saved = save();
    if (!saved.ok) return saved;
    return { ok: true, reason: REASON.OK, entry: next };
  }

  function update(id, patch) {
    const target = cleanId(id);
    if (!target) return { ok: false, reason: REASON.BAD_ID };
    const index = entries.findIndex((item) => item.id === target);
    if (index < 0) return { ok: false, reason: REASON.BAD_SHAPE };
    if (!isPlainObject(patch)) return { ok: false, reason: REASON.BAD_SHAPE };
    const now = clock();
    const merged = { ...entries[index], ...patch, id: target, updatedAt: now };
    const result = normalizeEntry(merged, rootDir, now);
    if (!result.ok) return { ok: false, reason: result.reason };
    entries[index] = result.entry;
    const saved = save();
    if (!saved.ok) return saved;
    return { ok: true, reason: REASON.OK, entry: entries[index] };
  }

  function snapshot() {
    return entries.map((item) => ({ ...item }));
  }

  function clear() {
    entries = [];
    const saved = save();
    return { ok: saved.ok, reason: saved.reason };
  }

  return {
    filePath,
    load,
    save,
    record,
    update,
    snapshot,
    clear,
    lastRejected: () => lastRejected.slice(),
  };
}

module.exports = {
  STATE,
  REASON,
  createDownloadJournal,
  describeJournalReject,
  DEFAULT_MAX_ENTRIES,
  DEFAULT_MAX_FILE_BYTES,
  DEFAULT_RETENTION_MS,
};
