'use strict';

const { safeInt, isPlainObject } = require('./modutil');

const fs = require('fs');
const path = require('path');
const downloadResume = require('./downloadresume');
const downloadReconcile = require('./downloadreconcile');

const { DEFAULT_MAX_ENTRIES, DEFAULT_MAX_FILE_BYTES, DEFAULT_RETENTION_MS, MAX_URL_CHARS, MAX_FILENAME_CHARS, MAX_PATH_CHARS, MAX_ID_CHARS, STATE, VALID_STATES, REASON, describeJournalReject, cleanId, cleanFilename, cleanURL, cleanPathWithin, normalizeEntry } = require('./journalentry');

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
      const stat = fsImpl.lstatSync(target);
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

  function reconcile(options = {}) {
    const now = clock();
    const exists = typeof options.exists === 'function' ? options.exists : (p) => partStats(p) !== null;
    const sizeOf = typeof options.sizeOf === 'function' ? options.sizeOf : (p) => partStats(p);
    const result = downloadReconcile.reconcileEntries(entries, {
      now,
      exists,
      sizeOf,
      maxVerify: options.maxVerify,
    });
    entries = result.entries;
    const saved = changesCount(result) > 0 ? save() : { ok: true, reason: REASON.OK };
    return {
      ok: saved.ok,
      reason: saved.reason,
      summary: result.summary,
      changes: result.changes,
    };
  }

  function changesCount(result) {
    return Array.isArray(result.changes) ? result.changes.length : 0;
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
    reconcile,
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
