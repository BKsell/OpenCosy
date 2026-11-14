'use strict';

function registerRuntimeTabsIpc(d) {
d.ipcMain.on('window-control', (event, action) => {
  if (!d.isMainSender(event)) return;
  switch (action) {
    case 'minimize': d.mainWindow.minimize(); break;
    case 'maximize': d.mainWindow.isMaximized() ? d.mainWindow.unmaximize() : d.mainWindow.maximize(); break;
    case 'close': d.mainWindow.close(); break;
  }
});

d.ipcMain.on('toggle-tabbar-collapse', (event, collapsed) => {
  if (!d.isMainSender(event)) return;
  d.isTabBarCollapsed = collapsed;
  d.updateBrowserViewBounds();
});

d.ipcMain.handle('navigate-tab', (event, { tabId, url }) => {
  if (!d.isMainSender(event)) return { success: false, error: 'Unauthorized' };
  if (!d.isSafeUrl(url)) return { success: false, error: 'Unsafe URL' };
  const tab = d.tabs.find(t => t.id === tabId);
  if (tab) {
    tab.url = url;
    d.loadTabContent(tab);
    d.sendToRenderer('tab-updated', { id: tab.id, url });
    return { success: true };
  }
  return { success: false };
});

d.ipcMain.handle('navigate-back', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  const wc = d.getCurrentTabWebContents();
  if (wc?.canGoBack()) { wc.goBack(); return { success: true }; }
  return { success: false };
});

d.ipcMain.handle('navigate-forward', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  const wc = d.getCurrentTabWebContents();
  if (wc?.canGoForward()) { wc.goForward(); return { success: true }; }
  return { success: false };
});

d.ipcMain.handle('reload-tab', (event, hard) => {
  if (!d.isMainSender(event)) return { success: false };
  const wc = d.getCurrentTabWebContents();
  if (!wc) return { success: false };
  if (hard) wc.reloadIgnoringCache(); else wc.reload();
  return { success: true };
});

d.ipcMain.handle('stop-loading', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  const wc = d.getCurrentTabWebContents();
  if (wc) wc.stop();
  return { success: true };
});

d.ipcMain.handle('duplicate-tab', (event, tabIndex) => {
  if (!d.isMainSender(event)) return { success: false };
  const idx = typeof tabIndex === 'number' && tabIndex >= 0 ? tabIndex : d.currentTabIndex;
  const tab = d.tabs[idx];
  if (!tab || !d.isSafeUrl(tab.url)) return { success: false };
  const newTab = d.createNewTab(tab.url);
  return { id: newTab.id, index: d.tabs.indexOf(newTab) };
});

// reopen-closed-tab 恢复最近关闭的标签（Ctrl+Shift+T）。
// recentlyClosedTabs 在入栈时已剔除 cosy:// 内置页，这里再做一次
// isSafeUrl 校验，防止历史数据被污染后恢复到危险协议。
d.ipcMain.handle('reopen-closed-tab', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  while (d.recentlyClosedTabs.length > 0) {
    const last = d.getLastClosedTab();
    if (!last || !last.url) continue;
    if (!d.isSafeUrl(last.url) || last.url.startsWith('cosy://')) continue;
    const tab = d.createNewTab(last.url);
    return { success: true, id: tab.id, index: d.tabs.indexOf(tab), url: last.url };
  }
  return { success: false, empty: true };
});

// get-recently-closed 供新标签页的“最近关闭”区块拉取（只读、不弹栈）：
// 快照字段经 downloadshelf 内核净化（剥控制字符/ANSI、限长），url 再走
// isSafeUrl 白名单，cosy:// 与危险协议绝不外泄。
d.ipcMain.handle('get-recently-closed', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  const items = [];
  for (let i = d.recentlyClosedTabs.length - 1; i >= 0 && items.length < 8; i--) {
    const t = d.recentlyClosedTabs[i];
    if (!t || !t.url || !d.isSafeUrl(t.url) || String(t.url).startsWith('cosy://')) continue;
    items.push({
      url: d.downloadShelf.truncateRunes(d.downloadShelf.stripControlChars(String(t.url)), 800),
      title: d.downloadShelf.truncateRunes(d.downloadShelf.stripControlChars(String(t.title || '')), 120),
      closedAt: Number.isFinite(Number(t.closedAt)) ? Number(t.closedAt) : null,
    });
  }
  return { success: true, items };
});

d.ipcMain.handle('create-tab', (event, url) => {
  if (!d.isMainSender(event)) return { success: false };
  if (!d.isSafeUrl(url)) url = 'cosy://newtab';
  const tab = d.createNewTab(url);
  return { id: tab.id, index: d.tabs.length - 1 };
});

d.ipcMain.handle('close-tab', (event, tabIndex) => {
  if (!d.isMainSender(event)) return { success: false };
  d.closeTab(tabIndex);
  return { success: true };
});

d.ipcMain.handle('switch-tab', (event, tabIndex) => {
  if (!d.isMainSender(event)) return { success: false };
  d.switchToTab(tabIndex);
  return { success: true };
});

// set-tab-pinned 固定 / 取消固定指定标签（默认当前标签）。重排与持久化都在
// 主进程完成，渲染层只据广播更新视图。
d.ipcMain.handle('set-tab-pinned', (event, payload = {}) => {
  if (!d.isMainSender(event)) return { success: false };
  const { tabId, pinned } = payload || {};
  const targetId = (tabId === undefined || tabId === null)
    ? (d.tabs[d.currentTabIndex] && d.tabs[d.currentTabIndex].id)
    : tabId;
  if (targetId === undefined || targetId === null) return { success: false };
  const r = d.applyPinnedState(targetId, !!pinned);
  if (!r.success) return { success: false, reason: r.reason };
  d.movePinnedTabsToFront();
  d.persistPins();
  return { success: true, pinned: !!pinned };
});

// toggle-tab-pinned 在固定 / 取消固定之间切换（供右键菜单与快捷键使用）。
d.ipcMain.handle('toggle-tab-pinned', (event, payload = {}) => {
  if (!d.isMainSender(event)) return { success: false };
  const tabId = (payload && payload.tabId !== undefined && payload.tabId !== null)
    ? payload.tabId
    : (d.tabs[d.currentTabIndex] && d.tabs[d.currentTabIndex].id);
  if (tabId === undefined || tabId === null) return { success: false };
  const r = d.toggleTabPinned(tabId);
  if (!r.success) return { success: false, reason: r.reason };
  return { success: true, pinned: !!r.pinned };
});

// close-tabs-batch 批量关闭（all/others/left/right）。固定标签由主进程内核统一
// 豁免，渲染层不再自行循环关闭，避免固定标签被“关闭其他 / 左侧 / 右侧”误关。
d.ipcMain.handle('close-tabs-batch', (event, payload = {}) => {
  if (!d.isMainSender(event)) return { success: false, closed: 0 };
  const mode = payload && payload.mode;
  const anchorId = payload && payload.anchorId;
  const r = d.planAndCloseTabs(mode, anchorId);
  if (!r.success) return { success: false, closed: 0 };
  return { success: true, closed: r.closed };
});
}

module.exports = { registerRuntimeTabsIpc };
