'use strict';

const MAX_TABS = 200;
const MAX_TITLE = 200;
const MAX_URL = 2048;
const MAX_SNAPSHOTS = 5;

const REASON = {
  OK: 'ok',
  EMPTY: 'empty',
  OVERLONG: 'overlong',
  BAD_URL: 'bad-url',
  BAD_PROTOCOL: 'bad-protocol',
  DUPLICATE: 'duplicate',
  TRUNCATED: 'truncated'
};

function normalizeTab(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const url = typeof raw.url === 'string' ? raw.url.trim() : '';
  if (!url || url.length > MAX_URL) return null;
  if (!/^https?:\/\//i.test(url)) return null;
  const title = typeof raw.title === 'string' ? raw.title.trim().slice(0, MAX_TITLE) : '';
  const pinned = raw.pinned === true;
  const index = Number.isSafeInteger(raw.index) && raw.index >= 0 ? raw.index : null;
  return { url, title, pinned, index };
}

function captureSession(windows) {
  if (!Array.isArray(windows)) return { ok: false, reason: REASON.BAD_URL, windows: [] };
  const out = [];
  let dropped = 0;
  for (const win of windows) {
    if (!win || typeof win !== 'object') continue;
    const tabs = Array.isArray(win.tabs) ? win.tabs : [];
    const kept = [];
    for (const tab of tabs) {
      if (kept.length >= MAX_TABS) {
        dropped += 1;
        continue;
      }
      const normalized = normalizeTab(tab);
      if (!normalized) {
        dropped += 1;
        continue;
      }
      kept.push(normalized);
    }
    if (kept.length === 0) continue;
    const activeIndex = Number.isSafeInteger(win.activeIndex) ? win.activeIndex : 0;
    out.push({
      tabs: kept,
      activeIndex: Math.min(Math.max(0, activeIndex), kept.length - 1)
    });
  }
  if (out.length === 0) return { ok: false, reason: REASON.EMPTY, windows: [] };
  return { ok: true, reason: dropped > 0 ? REASON.TRUNCATED : REASON.OK, windows: out, dropped };
}

function restoreSession(snapshot, limit) {
  const max = Number.isSafeInteger(limit) && limit > 0 ? limit : MAX_TABS;
  if (!snapshot || typeof snapshot !== 'object' || !Array.isArray(snapshot.windows)) {
    return { ok: false, reason: REASON.BAD_URL, windows: [] };
  }
  const seen = new Set();
  const windows = [];
  let duplicates = 0;
  let total = 0;
  for (const win of snapshot.windows) {
    if (total >= max) break;
    const tabs = [];
    const rawTabs = Array.isArray(win.tabs) ? win.tabs : [];
    for (const raw of rawTabs) {
      if (total >= max) break;
      const tab = normalizeTab(raw);
      if (!tab) continue;
      if (seen.has(tab.url)) {
        duplicates += 1;
        continue;
      }
      seen.add(tab.url);
      tabs.push(tab);
      total += 1;
    }
    if (tabs.length === 0) continue;
    windows.push({ tabs, activeIndex: 0 });
  }
  if (windows.length === 0) return { ok: false, reason: REASON.EMPTY, windows: [], duplicates };
  return { ok: true, reason: duplicates > 0 ? REASON.DUPLICATE : REASON.OK, windows, duplicates };
}

function mergeSessions(current, previous, limit) {
  const first = restoreSession(current, limit);
  const second = restoreSession(previous, limit);
  if (!first.ok && !second.ok) return { ok: false, reason: REASON.EMPTY, windows: [] };
  const seen = new Set();
  const windows = [];
  const push = (source) => {
    for (const win of source.windows) {
      const tabs = [];
      for (const tab of win.tabs) {
        if (seen.has(tab.url)) continue;
        seen.add(tab.url);
        tabs.push(tab);
      }
      if (tabs.length > 0) windows.push({ tabs, activeIndex: 0 });
    }
  };
  if (first.ok) push(first);
  if (second.ok) push(second);
  return { ok: windows.length > 0, reason: windows.length > 0 ? REASON.OK : REASON.EMPTY, windows };
}

function pruneSnapshots(snapshots) {
  if (!Array.isArray(snapshots)) return [];
  const kept = snapshots
    .filter((item) => item && typeof item === 'object' && Array.isArray(item.windows))
    .slice(0, MAX_SNAPSHOTS);
  return kept;
}

function countTabs(snapshot) {
  if (!snapshot || !Array.isArray(snapshot.windows)) return 0;
  return snapshot.windows.reduce((sum, win) => sum + (Array.isArray(win.tabs) ? win.tabs.length : 0), 0);
}

function describeSnapshot(snapshot) {
  const total = countTabs(snapshot);
  if (total === 0) return '无标签可恢复';
  const windows = Array.isArray(snapshot.windows) ? snapshot.windows.length : 0;
  return windows + ' 个窗口 · ' + total + ' 个标签';
}

module.exports = {
  MAX_TABS,
  MAX_SNAPSHOTS,
  REASON,
  captureSession,
  restoreSession,
  mergeSessions,
  pruneSnapshots,
  countTabs,
  describeSnapshot
};
