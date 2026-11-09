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
  try {
    const data = d.ledgerStore.readJSONStore(d.pinStorePath, null);
    if (!data || typeof data !== 'object') return [];
    return d.pinTabs.sanitizeStoredPinEntries(data.entries);
  } catch (e) {
    console.error('读取固定标签失败:', e);
    return [];
  }
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
function rehydrateTabGroups() {
  const stored = d.loadStoredTabGroups();
  if (!stored.length) return 0;
  const current = d.tabs.map(t => ({ id: t.id, pinned: !!t.pinned }));
  const clean = d.tabGroups.rehydrateGroupsByTabs(stored, current);
  d.tabGroupModel.loadStored(clean);
  if (d.tabGroupModel.groupCount() > 0) {
    d.applyTabGroupArrangement();
    d.broadcastTabGroups();
  }
  return d.tabGroupModel.groupCount();
}
function sanitizeDownloadFilename(name) {
  if (!name || typeof name !== 'string') return 'download';
  const res = d.dloadGuard.sanitizeName(name);
  if (res.rejected || !res.name) return 'download';
  // 双保险：dloadguard 已剥目录，这里再清一遍 Windows/Unix 保留字符。
  const final = d.downloadName.sanitizeDownloadName(res.name, 'download');
  if (final.changed) {
    d.recordSecurityEvent('download-name', 'info',
      `下载文件名已净化（${final.reasons.join(',')}）`, '');
  }
  return final.name || 'download';
}
function resolveUniqueDownloadPath(dir, filename) {
  let existingNames = [];
  try {
    existingNames = d.fsSync.readdirSync(dir);
  } catch (scanError) {
    existingNames = [];
  }
  const allocation = d.downloadPathCollision.claimUniquePath({ dir, filename, taken: existingNames });
  if (!allocation.ok) {
    d.recordSecurityEvent('download-savepath', 'critical',
      `无法分配唯一下载文件名: ${d.downloadPathCollision.describeAllocation(allocation)}`, 'download-manager');
    return '';
  }
  return allocation.path;
}
function rememberDownloadOrigin(savePath, originUrl) {
  if (!savePath || !originUrl) return;
  if (d.downloadOriginByPath.size >= d.MAX_DOWNLOAD_ORIGIN_ENTRIES) {
    const oldest = d.downloadOriginByPath.keys().next().value;
    d.downloadOriginByPath.delete(oldest);
  }
  d.downloadOriginByPath.set(savePath, originUrl);
}
function persistDownloadRisks() {
  if (d.downloadRiskSaveTimer) clearTimeout(d.downloadRiskSaveTimer);
  d.downloadRiskSaveTimer = setTimeout(() => {
    try {
      d.ledgerStore.writeJSONStore(d.downloadRiskStorePath, { version: 1, records: d.downloadRiskRecords });
    } catch {}
  }, 300);
}
function recordDownloadRisk(entry) {
  d.loadDownloadRisks();
  d.downloadRiskRecords.push({
    time: Date.now(),
    filename: String(entry.filename || '').slice(0, 255),
    host: String(entry.host || '').slice(0, 255),
    decision: entry.decision || 'warn',
    action: entry.action || 'saved',
    ext: String(entry.ext || '').slice(0, 32),
    risks: Array.isArray(entry.risks) ? entry.risks.slice(0, 20) : [],
  });
  if (d.downloadRiskRecords.length > d.MAX_DOWNLOAD_RISK_RECORDS) {
    d.downloadRiskRecords.splice(0, d.downloadRiskRecords.length - d.MAX_DOWNLOAD_RISK_RECORDS);
  }
  persistDownloadRisks();
}
function listDownloadRisks(limit) {
  d.loadDownloadRisks();
  const max = Math.max(1, Math.min(500, Number(limit) || 200));
  return d.downloadRiskRecords.slice(-max).reverse().map(r => ({ ...r, risks: r.risks || [] }));
}
function clearDownloadRisks() {
  d.loadDownloadRisks();
  const n = d.downloadRiskRecords.length;
  d.downloadRiskRecords.length = 0;
  persistDownloadRisks();
  return n;
}
function analyzeDownloadSafety(filename, mime) {
  return d.dloadGuard.analyzeDownloadName(filename, mime);
}
function handleDownloadEvent(event, item, webContents) {
  return require('./downloadsevents').handleDownloadEvent(d.handleDownloadEventCtx, event, item, webContents);
}
function downloadJournalFileProbe() {
  return {
    exists: (target) => {
      try { return d.fsSync.lstatSync(target).isFile(); } catch { return false; }
    },
    sizeOf: (target) => {
      try {
        const stat = d.fsSync.lstatSync(target);
        return stat.isFile() ? stat.size : null;
      } catch { return null; }
    },
  };
}
function attachDownloadManager(sess) {
  if (!sess || d.managedDownloadSessions.has(sess)) return;
  try {
    sess.on('will-download', handleDownloadEvent);
    d.managedDownloadSessions.add(sess);
  } catch {}
}
function setupDownloadManager() {
  attachDownloadManager(d.session.defaultSession);
}
function formatSpeed(bytesPerSecond) {
  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
  let speed = bytesPerSecond;
  let unitIndex = 0;
  while (speed >= 1024 && unitIndex < units.length - 1) { speed /= 1024; unitIndex++; }
  return speed.toFixed(2) + ' ' + units[unitIndex];
}
function reviewToOpenUrl(review) {
  if (!review || !review.ok) return null;
  if (review.kind === 'local-html') {
    if (!d.fsSync.existsSync(review.value)) return null;
    return d.pathToFileURL(review.value).href;
  }
  return review.value; // web / internal 均已是规范化 href
}
function resolveStartupDeepLink(rawArg, source) {
  const review = d.deeplinkGuard.reviewStartupArg(rawArg);
  if (!review.ok) {
    d.recordSecurityEvent('deeplink-blocked', 'warn',
      `启动深链被拦截（来源:${source}，${d.deeplinkGuard.describeReason(review.reason)}）`, '');
    return null;
  }
  return reviewToOpenUrl(review);
}
function resolveStartupArgv(argv) {
  const review = d.deeplinkGuard.pickDeepLinkFromArgv(argv);
  return review ? reviewToOpenUrl(review) : null;
}
function applyFind(forward = true) {
  const wc = d.getCurrentTabWebContents();
  if (!wc || !d.findState.text) return;
  wc.findInPage(d.findState.text, {
    forward,
    matchCase: !!d.findState.matchCase,
    wholeWord: !!d.findState.wholeWord,
  });
}
function createContextMenu(menuType, selectedText = '') {
  const menu = new d.Menu();
  if (menuType === 'selection') {
    if (selectedText) {
      menu.append(new d.MenuItem({ label: '复制', click: () => { if (d.mainWindow?.webContents) d.mainWindow.webContents.copy(); } }));
      menu.append(new d.MenuItem({ type: 'separator' }));
    }
    menu.append(new d.MenuItem({ label: '主页', click: d.goHome }));
    menu.append(new d.MenuItem({ label: '设置', click: () => d.createNewTab('cosy://setting') }));
    menu.append(new d.MenuItem({ type: 'separator' }));
    if (d.isDev) menu.append(new d.MenuItem({ label: '开发者工具', click: d.toggleDevTools }));
  } else {
    if (d.isDev) menu.append(new d.MenuItem({ label: '开发者工具', click: d.toggleDevTools }));
    menu.append(new d.MenuItem({ label: '返回主页', click: d.goHome }));
    menu.append(new d.MenuItem({ label: '设置', click: () => d.createNewTab('cosy://setting') }));
  }
  return menu;
}
function sanitizeSettings(raw) {
  if (!raw || typeof raw !== 'object') return {};
  const clean = {};
  for (const [key, validate] of Object.entries(d.ALLOWED_SETTING_KEYS)) {
    if (key in raw && validate(raw[key])) clean[key] = raw[key];
  }
  return clean;
}
function sanitizeBookmarkLike(b) {
  return {
    url: typeof b.url === 'string' ? b.url.slice(0, 8192) : '',
    title: typeof b.title === 'string' ? b.title.slice(0, 300) : '',
    addedDate: typeof b.addedDate === 'string' ? b.addedDate : '',
  };
}
function openUrlFromInternalFrame(frameOk, url) {
  if (!frameOk) return { ok: false, error: 'denied' };
  const isInternal = typeof url === 'string' && url.startsWith('cosy://');
  if (!d.isSafeUrl(url) && !isInternal) return { ok: false, error: 'bad-url' };
  const tab = d.createNewTab(url);
  return { ok: true, id: tab.id, index: d.tabs.length - 1 };
}
function addToReadingList(url, title) {
  if (!d.isSafeUrl(url)) return { ok: false, error: 'bad-url' };
  let t = typeof title === 'string' ? title : '';
  t = t.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 300).trim();
  if (d.readingList.some(b => String(b.url || '') === url)) return { ok: true, added: false };
  d.readingList.push({ url, title: t || url, addedDate: new Date().toISOString() });
  d.saveReadingList();
  return { ok: true, added: true };
}
function customRulesSnapshot() {
  return {
    host: d.customRules.host.slice(),
    glob: d.customRules.glob.slice(),
    path: d.customRules.path.slice(),
    count: d.blockRules.ruleCount(d.customRules),
  };
}
function vaultPasswordOK(pw) {
  if (typeof pw !== 'string') return false;
  if (pw.length < 1 || pw.length > 256) return false;
  if (/[\x00-\x1f\x7f]/.test(pw)) return false;
  if (/^\s*$/.test(pw)) return false;
  try {
    return Buffer.byteLength(pw, 'utf8') <= 1024;
  } catch {
    return false;
  }
}
function originOfUrl(u) {
  return d.urlResolve.safeOrigin(u, '');
}
module.exports = { bindDeps, savePinsNow, persistPins, loadStoredPins, clearStoredPins, findTabIndexById, broadcastPinnedState, applyPinnedState, movePinnedTabsToFront, pinTab, unpinTab, toggleTabPinned, rehydratePinnedTabs, ensurePinnedTabsOpened, closeTabsByIds, planAndCloseTabs, rehydrateTabGroups, sanitizeDownloadFilename, resolveUniqueDownloadPath, rememberDownloadOrigin, persistDownloadRisks, recordDownloadRisk, listDownloadRisks, clearDownloadRisks, analyzeDownloadSafety, handleDownloadEvent, downloadJournalFileProbe, attachDownloadManager, setupDownloadManager, formatSpeed, reviewToOpenUrl, resolveStartupDeepLink, resolveStartupArgv, applyFind, createContextMenu, sanitizeSettings, sanitizeBookmarkLike, openUrlFromInternalFrame, addToReadingList, customRulesSnapshot, vaultPasswordOK, originOfUrl };
