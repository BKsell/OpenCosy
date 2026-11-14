'use strict';

const MIN_ZOOM = 0.25;
const MAX_ZOOM = 5;
const ZOOM_STEPS = [0.5, 0.67, 0.8, 0.9, 1, 1.1, 1.25, 1.5, 1.75, 2, 2.5, 3, 4, 5];
const MAX_ENTRIES = 512;

function normalizeLevel(value) {
  const level = Number(value);
  if (!Number.isFinite(level)) return null;
  return Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, Math.round(level * 100) / 100));
}

function stepLevel(current, direction) {
  const level = normalizeLevel(current);
  if (level === null) return null;
  if (direction === 'reset') return 1;
  const index = ZOOM_STEPS.findIndex((item) => item >= level);
  if (direction === 'in') {
    if (index < 0) return MAX_ZOOM;
    const next = index + (ZOOM_STEPS[index] === level ? 1 : 0);
    return ZOOM_STEPS[Math.min(ZOOM_STEPS.length - 1, next)];
  }
  if (direction === 'out') {
    if (index < 0) return MAX_ZOOM;
    if (ZOOM_STEPS[index] === level) return ZOOM_STEPS[Math.max(0, index - 1)];
    return ZOOM_STEPS[index];
  }
  return null;
}

function normalizeOrigin(origin) {
  if (typeof origin !== 'string') return null;
  let text = origin.trim().toLowerCase();
  if (!text) return null;
  text = text.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  const cut = text.search(/[/?#]/);
  if (cut >= 0) text = text.slice(0, cut);
  const at = text.lastIndexOf('@');
  if (at >= 0) text = text.slice(at + 1);
  const colon = text.indexOf(':');
  if (colon >= 0) text = text.slice(0, colon);
  if (!text || text.length > 255) return null;
  if (!/^[a-z0-9._-]+$/.test(text)) return null;
  return text;
}

function createStore() {
  return { entries: {}, updatedAt: 0 };
}

function readStore(store) {
  if (!store || typeof store !== 'object') return createStore();
  if (!store.entries || typeof store.entries !== 'object') return createStore();
  return store;
}

function remember(store, origin, value) {
  const key = normalizeOrigin(origin);
  const level = normalizeLevel(value);
  if (!key || level === null) return { ok: false, reason: !key ? 'bad-origin' : 'bad-level', store: readStore(store) };
  const base = readStore(store);
  const entries = Object.assign({}, base.entries, { [key]: level });
  const pruned = prune(entries);
  return { ok: true, reason: 'ok', store: { entries: pruned, updatedAt: Date.now() } };
}

function recall(store, origin) {
  const key = normalizeOrigin(origin);
  if (!key) return { ok: false, reason: 'bad-origin', level: 1 };
  const base = readStore(store);
  const level = base.entries[key];
  if (level === undefined) return { ok: true, reason: 'default', level: 1 };
  return { ok: true, reason: 'ok', level: normalizeLevel(level) || 1 };
}

function forget(store, origin) {
  const key = normalizeOrigin(origin);
  if (!key) return { ok: false, reason: 'bad-origin', store: readStore(store) };
  const base = readStore(store);
  const entries = Object.assign({}, base.entries);
  delete entries[key];
  return { ok: true, reason: 'ok', store: { entries, updatedAt: Date.now() } };
}

function prune(entries) {
  const keys = Object.keys(entries);
  if (keys.length <= MAX_ENTRIES) return entries;
  const kept = {};
  const sorted = keys.sort((a, b) => String(a).localeCompare(String(b)));
  for (const key of sorted.slice(sorted.length - MAX_ENTRIES)) {
    kept[key] = entries[key];
  }
  return kept;
}

function listSites(store) {
  const base = readStore(store);
  return Object.keys(base.entries).map((origin) => ({ origin, level: base.entries[origin] }));
}

function describeLevel(level) {
  const normalized = normalizeLevel(level);
  if (normalized === null) return '未知缩放';
  return Math.round(normalized * 100) + '%';
}

module.exports = {
  MIN_ZOOM,
  MAX_ZOOM,
  ZOOM_STEPS,
  normalizeLevel,
  stepLevel,
  normalizeOrigin,
  createStore,
  remember,
  recall,
  forget,
  listSites,
  describeLevel
};
