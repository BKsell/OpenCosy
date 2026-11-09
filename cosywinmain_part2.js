let d = {};

function recordCrash(tab, details) {
  const now = Date.now();
  tab.crashEvents = (tab.crashEvents || []).filter(t => now - t < d.CRASH_WINDOW_MS);
  tab.crashEvents.push(now);
  tab.crashed = true;
  tab.crashReason = d.CRASH_REASON_TEXT[details?.reason]
    || `渲染进程异常退出（${details?.reason || 'unknown'}）`;
  d.sendToRenderer('tab-crashed', { id: tab.id, reason: tab.crashReason });
}

function canAutoRecover(tab) {
  return (tab.crashEvents || []).length <= d.MAX_CRASH_AUTO_RECOVER;
}

function destroyTabView(tab) {
  if (!tab.view) return;
  try { d.mainWindow.contentView.removeChildView(tab.view); } catch {}
  try { tab.view.webContents.destroy(); } catch {}
  tab.view = null;
}

function rebuildCrashedTab(tab) {
  const reason = tab.crashReason;
  const overLimit = !canAutoRecover(tab);
  destroyTabView(tab);
  tab.crashed = false;
  tab.crashReason = null;
  loadTabContent(tab);
  if (overLimit) {
    showCosyError(tab, '500', reason || '页面崩溃', '该页面短时间内多次崩溃，已停止自动恢复，请手动刷新');
  }
}

function handleRenderProcessGone(tab, details) {
  if (!tab) return;
  recordCrash(tab, details);
  const idx = d.tabs.indexOf(tab);
  // 活动标签立即恢复；后台标签只清理死视图，等切回时再重建。
  if (idx === d.currentTabIndex) rebuildCrashedTab(tab);
  else destroyTabView(tab);
}

function discardTab(tab, reason = 'idle') {
  if (d.tabKeepsAlive(tab)) return false;
  destroyTabView(tab);
  tab.discarded = true;
  tab.retry403 = false;
  d.sendToRenderer('tab-discarded', { id: tab.id, url: tab.url, reason });
  return true;
}

function reloadDiscardedTab(tab) {
  if (!tab || !tab.discarded) return false;
  tab.discarded = false;
  tab.lastActiveAt = Date.now();
  loadTabContent(tab);
  d.sendToRenderer('tab-reloaded', { id: tab.id });
  setTimeout(d.updateBrowserViewBounds, 0);
  return true;
}

function sweepDiscardableTabs() {
  if (!d.memorySaverEnabled) return;
  const now = Date.now();
  for (const tab of d.tabs) {
    if (d.tabKeepsAlive(tab)) continue;
    if (now - (tab.lastActiveAt || 0) >= d.MEMORY_SAVER_IDLE_MS) discardTab(tab, 'idle');
  }
}

function startMemorySaver() {
  if (d.memorySaverTimer) return;
  d.memorySaverTimer = setInterval(sweepDiscardableTabs, d.MEMORY_SAVER_SWEEP_MS);
  if (typeof d.memorySaverTimer.unref === 'function') d.memorySaverTimer.unref();
}

function discardAllBackgroundTabs() {
  let n = 0;
  for (const tab of d.tabs) {
    if (d.tabKeepsAlive(tab)) continue;
    if (discardTab(tab, 'manual')) n++;
  }
  return n;
}

function buildTabPidMap() {
  const map = new Map();
  for (let i = 0; i < d.tabs.length; i++) {
    const tab = d.tabs[i];
    const wc = tab && tab.view && tab.view.webContents;
    if (!wc || typeof wc.getOSProcessId !== 'function') continue;
    let pid;
    try { pid = wc.getOSProcessId(); } catch { continue; }
    if (Number.isInteger(pid) && pid > 0 && !map.has(pid)) {
      map.set(pid, { id: String(tab.id), title: String(tab.title || tab.url || ''), index: i });
    }
  }
  return map;
}

function loadTabContent(tab) {
  return require('./tabcontent').loadTabContent(d.loadTabContentCtx, tab);
}

function showCosyError(tab, code, message, reason) {
  const errorParams = new URLSearchParams({ code, message, reason, url: tab.url, browserCode: -3, browserMessage: 'ERR_UNKNOWN_COSY_URL' });
  const errorUrl = `file://${__dirname}/src/error.html?${errorParams.toString()}`;
  tab.view.webContents.loadURL(errorUrl);
  tab.title = `错误 - ${code}`;
  tab.favicon = 'src/error.png';
  d.sendToRenderer('tab-updated', { id: tab.id, url: tab.url, title: tab.title });
}

function bindDeps(x) { d = x; }

module.exports = { recordCrash, canAutoRecover, destroyTabView, rebuildCrashedTab, handleRenderProcessGone, discardTab, reloadDiscardedTab, sweepDiscardableTabs, startMemorySaver, discardAllBackgroundTabs, buildTabPidMap, loadTabContent, showCosyError, bindDeps };
