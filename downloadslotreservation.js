'use strict';

const path = require('path');

const REASON = {
  OK: 'ok',
  TAKEN: 'taken',
  INVALID_PATH: 'invalid-path',
  INVALID_ID: 'invalid-id',
};

const DEFAULT_TTL_MS = 6 * 60 * 60 * 1000;

function normalizeKey(targetPath, caseInsensitive) {
  const resolved = path.resolve(String(targetPath || ''));
  const normalized = path.normalize(resolved);
  return caseInsensitive ? normalized.toLowerCase() : normalized;
}

function createSlotReservation(options = {}) {
  const ttlMs = Number.isFinite(options.ttlMs) && options.ttlMs > 0 ? options.ttlMs : DEFAULT_TTL_MS;
  const now = typeof options.now === 'function' ? options.now : Date.now;
  const caseInsensitive = options.caseInsensitive !== false;
  const entries = new Map();

  function sweep() {
    const current = Number(now());
    for (const [key, entry] of entries) {
      if (entry.expiresAt <= current) entries.delete(key);
    }
  }

  function reserve(input = {}) {
    sweep();
    const id = String(input.id || '');
    const targetPath = String(input.path || '');
    if (!id) return { ok: false, reason: REASON.INVALID_ID, key: '', conflictingId: '' };
    if (!targetPath || !path.isAbsolute(targetPath)) {
      return { ok: false, reason: REASON.INVALID_PATH, key: '', conflictingId: '' };
    }
    const key = normalizeKey(targetPath, caseInsensitive);
    const existing = entries.get(key);
    if (existing && existing.id !== id) {
      return { ok: false, reason: REASON.TAKEN, key, conflictingId: existing.id };
    }
    const current = Number(now());
    entries.set(key, {
      id,
      key,
      path: path.normalize(path.resolve(targetPath)),
      createdAt: existing ? existing.createdAt : current,
      expiresAt: current + ttlMs,
    });
    return { ok: true, reason: REASON.OK, key, conflictingId: '' };
  }

  function release(id) {
    const target = String(id || '');
    let removed = 0;
    for (const [key, entry] of entries) {
      if (entry.id === target) {
        entries.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  function releasePath(targetPath) {
    const key = normalizeKey(targetPath, caseInsensitive);
    const entry = entries.get(key);
    if (!entry) return '';
    entries.delete(key);
    return entry.id;
  }

  function has(targetPath) {
    sweep();
    return entries.has(normalizeKey(targetPath, caseInsensitive));
  }

  function snapshot() {
    sweep();
    return Array.from(entries.values())
      .sort((a, b) => a.createdAt - b.createdAt)
      .map((entry) => ({ id: entry.id, key: entry.key, path: entry.path, expiresAt: entry.expiresAt }));
  }

  function size() {
    sweep();
    return entries.size;
  }

  return { reserve, release, releasePath, has, snapshot, size };
}

module.exports = { REASON, DEFAULT_TTL_MS, createSlotReservation };
