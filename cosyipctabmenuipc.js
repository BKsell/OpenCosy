'use strict';

function registerTabMenuIpc(d) {
d.ipcMain.on('show-tab-context-menu', (event, payload) => {
  if (!d.isMainSender(event)) return;
  const tabId = payload && payload.tabId;
  const idx = d.findTabIndexById(tabId);
  if (idx < 0) return;
  const tab = d.tabs[idx];
  const safeUrl = (typeof tab.url === 'string' && tab.url.length <= 2048) ? tab.url : '';
  const safeTitle = (typeof tab.title === 'string' && tab.title.length <= 300) ? tab.title : '';
  const menu = new d.Menu();
  menu.append(new d.MenuItem({
    label: '在新标签页中打开',
    enabled: Boolean(safeUrl),
    click: () => { if (safeUrl) d.createNewTab(safeUrl); }
  }));
  menu.append(new d.MenuItem({
    label: '复制链接地址',
    enabled: Boolean(safeUrl),
    click: () => { if (safeUrl) d.clipboard.writeText(safeUrl); }
  }));
  menu.append(new d.MenuItem({
    label: '复制标题',
    enabled: Boolean(safeTitle),
    click: () => { if (safeTitle) d.clipboard.writeText(safeTitle); }
  }));
  menu.append(new d.MenuItem({ type: 'separator' }));
  menu.append(new d.MenuItem({
    label: '重新加载',
    click: () => { if (tab.view && tab.view.webContents) tab.view.webContents.reload(); }
  }));
  menu.append(new d.MenuItem({ type: 'separator' }));
  menu.append(new d.MenuItem({
    label: tab.pinned ? '取消固定标签页' : '固定标签页',
    click: () => d.toggleTabPinned(tab.id)
  }));
  menu.append(new d.MenuItem({
    label: tab.muted ? '取消静音标签页' : '静音标签页',
    click: () => {
      if (!tab.view || !tab.view.webContents) return;
      tab.muted = !tab.muted;
      tab.view.webContents.setAudioMuted(tab.muted);
      try { tab.audible = !!tab.view.webContents.isCurrentlyAudible(); } catch {}
      d.sendToRenderer('tab-audio-changed', { id: tab.id, audible: tab.audible, muted: tab.muted });
    }
  }));
  menu.append(new d.MenuItem({ type: 'separator' }));
  menu.append(new d.MenuItem({
    label: '关闭标签页',
    click: () => { d.closeTabsByIds([tab.id]); }
  }));
  menu.append(new d.MenuItem({
    label: '关闭其他标签页',
    click: () => { d.planAndCloseTabs('others', tab.id); }
  }));
  menu.popup({ window: d.mainWindow });
});

// ===== 书签栏显隐的查询与持久化 =====
// 顶栏书签栏的显隐是用户偏好：切换后写回 cosySettings.json（复用 sanitizeSettings
// 白名单校验），启动时恢复。查询走 invoke（渲染层只读），切换走 send（受信帧）。
d.ipcMain.handle('get-bookmark-bar-visible', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  return { success: true, visible: d.bookmarkBarVisible };
});

d.ipcMain.on('set-bookmark-bar-visible', (event, payload) => {
  if (!d.isMainSender(event)) return;
  const next = !!(payload && payload.visible);
  if (next === d.bookmarkBarVisible) return;
  d.bookmarkBarVisible = next;
  try {
    const settingsPath = d.path.join(d.app.getPath('userData'), 'cosySettings.json');
    const cur = d.readStoredSettings();
    cur.bookmarkBarVisible = next;
    d.ledgerStore.writeJSONStore(settingsPath, d.sanitizeSettings(cur), { pretty: true });
  } catch (e) {
    console.error('保存书签栏显隐失败:', e);
  }
});
}

module.exports = { registerTabMenuIpc };
