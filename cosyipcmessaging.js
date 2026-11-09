'use strict';

const { registerDownloadIpc } = require('./cosyipcdownloadipc');

let d = {};

function bindDeps(x) {
  d = x;
}

function registerMessagingIpc() {
d.ipcMain.handle('set-tab-muted', (event, payload = {}) => {
  if (!d.isMainSender(event)) return { success: false };
  const { tabId, muted } = payload || {};
  const tab = (tabId === undefined || tabId === null)
    ? d.tabs[d.currentTabIndex]
    : d.tabs.find(t => String(t.id) === String(tabId));
  if (!tab || !tab.view || !tab.view.webContents) return { success: false };
  tab.muted = !!muted;
  tab.view.webContents.setAudioMuted(tab.muted);
  try { tab.audible = !!tab.view.webContents.isCurrentlyAudible(); } catch {}
  d.sendToRenderer('tab-audio-changed', { id: tab.id, audible: tab.audible, muted: tab.muted });
  return { success: true, muted: tab.muted };
});

// set-zoom 调整当前标签缩放。delta 为档位变化（Chrome 每档约 1.1/0.9 倍），
// factor 直接指定（Ctrl+0 复位为 1）。按 origin 记忆，导航后自动恢复。
d.ipcMain.handle('set-zoom', (event, payload = {}) => {
  if (!d.isMainSender(event)) return { success: false };
  const result = d.adjustCurrentZoom(payload || {});
  if (!result) return { success: false };
  return { success: true, factor: result.factor, percent: result.percent };
});

d.ipcMain.on('navigate-to-url', (event, url) => {
  if (!d.isMainSender(event)) return;
  if (url && d.isSafeUrl(url)) d.createNewTab(url);
});

  registerDownloadIpc(d);
d.ipcMain.handle('get-current-tab', (event) => {
  if (!d.isMainSender(event)) return null;
  if (d.tabs.length > 0 && d.currentTabIndex >= 0) {
    const tab = d.tabs[d.currentTabIndex];
    return {
      id: tab.id, url: tab.url, title: tab.title, favicon: tab.favicon,
      isLoading: tab.isLoading, canGoBack: tab.canGoBack, canGoForward: tab.canGoForward
    };
  }
  return null;
});

d.ipcMain.handle('get-all-tabs', (event) => {
  if (!d.isMainSender(event)) return [];
  return d.tabs.map(tab => ({
    id: tab.id, url: tab.url, title: tab.title, favicon: tab.favicon,
    isLoading: tab.isLoading, canGoBack: tab.canGoBack, canGoForward: tab.canGoForward,
    discarded: !!tab.discarded, pinned: !!tab.pinned
  }));
});

// search-tabs：在“当前权威 tabs 列表”上跑纯逻辑标签搜索。匹配/排序全部在
// tabsearch 内核完成，这里只喂 id/title/url/pinned，结果里的 index 即当前 tabs
// 下标，渲染层回车时直接复用 switch-tab(index) 切换，不需要新增激活通道。
d.ipcMain.handle('search-tabs', (event, query) => {
  if (!d.isMainSender(event)) return [];
  const q = typeof query === 'string' ? query : '';
  const snapshot = d.tabs.map(tab => ({
    id: tab.id,
    title: typeof tab.title === 'string' ? tab.title : '',
    url: typeof tab.url === 'string' ? tab.url : '',
    pinned: !!tab.pinned,
  }));
  return d.tabSearch.searchTabs(snapshot, q);
});

d.ipcMain.on('close-current-tab', (event) => {
  if (!d.isMainSender(event)) return;
  if (d.tabs.length > 0) d.closeTab(d.currentTabIndex);
});
}

module.exports = { bindDeps, registerMessagingIpc };
