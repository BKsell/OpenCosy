const { readStoredSection } = require('./modutil_core');

let d = {};
function bindDeps(x) {
  d = x;
}
function savePinsNow() {
  try {
    // 跨重启运行时 id 会重新生成，因此按 URL 记录固定标签，重水合时再匹配新 id。
    const entries = [];
    for (const id of d.pinModel.ids()) {
      const t = d.tabs.find(tab => tab && tab.id === id);
      if (t && t.url) entries.push({ id, url: t.url });
    }
    d.ledgerStore.writeJSONStore(d.pinStorePath, { version: 1, entries });
  } catch (e) {
    console.error('保存固定标签失败:', e);
  }
}
function persistPins() {
  if (d.pinSaveTimer) clearTimeout(d.pinSaveTimer);
  d.pinSaveTimer = setTimeout(savePinsNow, 400);
}
function loadStoredPins() {
  return readStoredSection(d.ledgerStore.readJSONStore, d.pinStorePath,
    data => d.pinTabs.sanitizeStoredPinEntries(data.entries), '读取固定标签失败:');
}
function clearStoredPins() {
  try {
    if (d.fsSync.existsSync(d.pinStorePath)) d.fsSync.unlinkSync(d.pinStorePath);
  } catch (e) {
    console.error('清除固定标签失败:', e);
  }
}
function findTabIndexById(tabId) {
  return d.tabs.findIndex(t => t && String(t.id) === String(tabId));
}
function broadcastPinnedState(tab) {
  d.sendToRenderer('tab-pinned-changed', { id: tab.id, pinned: !!tab.pinned });
}
function applyPinnedState(tabId, pinned) {
  const idx = findTabIndexById(tabId);
  if (idx < 0) return { success: false };
  const tab = d.tabs[idx];
  const want = !!pinned;
  if (want) {
    const r = d.pinModel.pin(tab.id);
    if (!r.ok) return { success: false, reason: r.reason };
  } else {
    const r = d.pinModel.unpin(tab.id);
    if (!r.ok) return { success: false, reason: r.reason };
  }
  tab.pinned = want;
  broadcastPinnedState(tab);
  return { success: true, pinned: want, changed: true };
}
function movePinnedTabsToFront() {
  const ordered = d.pinModel.arrange(d.tabs.map(t => t.id));
  if (ordered.length !== d.tabs.length) return false;
  const byId = new Map(d.tabs.map(t => [t.id, t]));
  const next = ordered.map(id => byId.get(id));
  const currentTab = d.tabs[d.currentTabIndex];
  for (let i = 0; i < d.tabs.length; i++) d.tabs[i] = next[i];
  if (currentTab) {
    const ni = d.tabs.indexOf(currentTab);
    if (ni >= 0) d.currentTabIndex = ni;
  }
  d.sendToRenderer('pins-order-changed', { ids: d.pinModel.ids() });
  return true;
}
function pinTab(tabId) {
  const r = applyPinnedState(tabId, true);
  if (!r.success) return r;
  movePinnedTabsToFront();
  persistPins();
  return r;
}
function unpinTab(tabId) {
  const r = applyPinnedState(tabId, false);
  if (!r.success) return r;
  movePinnedTabsToFront();
  persistPins();
  return r;
}
function toggleTabPinned(tabId) {
  const idx = findTabIndexById(tabId);
  if (idx < 0) return { success: false };
  return d.tabs[idx].pinned ? unpinTab(d.tabs[idx].id) : pinTab(d.tabs[idx].id);
}
function rehydratePinnedTabs() {
  const stored = loadStoredPins();
  if (!stored.length) return 0;
  const current = d.tabs.map(t => ({ id: t.id, url: t.url }));
  const pinnedIds = d.pinTabs.rehydratePinsByUrl(stored, current);
  for (const id of pinnedIds) {
    const r = applyPinnedState(id, true);
    if (!r.success) continue;
  }
  if (d.pinModel.count() > 0) movePinnedTabsToFront();
  return d.pinModel.count();
}
function ensurePinnedTabsOpened() {
  const stored = loadStoredPins();
  if (!stored.length) return 0;
  const haveUrls = new Set(d.tabs.map(t => t.url));
  for (const rec of stored) {
    if (haveUrls.has(rec.url)) continue;
    if (d.getUrlProtocol(rec.url) === 'cosy:') continue;
    if (!d.isSafeUrl(rec.url)) continue;
    haveUrls.add(rec.url);
    d.createNewTab(rec.url);
  }
  return rehydratePinnedTabs();
}
function closeTabsByIds(ids) {
  const indexes = [];
  for (const id of ids) {
    const i = findTabIndexById(id);
    if (i >= 0) indexes.push(i);
  }
  indexes.sort((a, b) => b - a);
  for (const i of indexes) d.closeTab(i);
  return indexes.length;
}
function planAndCloseTabs(mode, anchorId) {
  const plan = d.pinTabs.planBatchClose(
    d.tabs.map(t => ({ id: t.id, pinned: !!t.pinned })),
    { mode, anchorId }
  );
  if (!plan) return { success: false, closed: 0 };
  const closed = closeTabsByIds(plan.closeIds);
  return { success: true, closed, kept: plan.keepIds };
}

const downloadTabSurface = require('./cosytabsdownload_core');

function bindDepsAll(x) {
  d = x;
  downloadTabSurface.bindDeps(x);
}

module.exports = Object.assign({ bindDeps: bindDepsAll }, downloadTabSurface, { savePinsNow, persistPins, loadStoredPins, clearStoredPins, findTabIndexById, broadcastPinnedState, applyPinnedState, movePinnedTabsToFront, pinTab, unpinTab, toggleTabPinned, rehydratePinnedTabs, ensurePinnedTabsOpened, closeTabsByIds, planAndCloseTabs });
