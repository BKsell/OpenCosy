'use strict';

let d = {};

function bindDeps(x) {
  d = x;
}

function registerFindIpc() {
d.ipcMain.on('find-in-page', (event, payload) => {
  if (!d.isMainSender(event)) return;
  const { text, forward, matchCase, wholeWord } = payload || {};
  // 输入与频率全部过 findguard：拒非字符串 / 超长 / 控制字符，合并极短重复提交，
  // 按键洪泛时进入短暂冷却，避免超长 query 匹配与 found-in-page 广播拖慢渲染进程。
  const v = d.findGuard.decideFind(
    d.findRateState,
    { text, matchCase: !!matchCase, wholeWord: !!wholeWord },
    Date.now()
  );
  if (v.decision === d.findGuard.FIND_REJECT) {
    const severity = (v.reason === d.findGuard.HOLD_BURST || v.reason === d.findGuard.HOLD_COOLDOWN)
      ? 'info' : 'warn';
    d.recordSecurityEvent('find-rate-limited', severity, d.findGuard.describeFindReason(v.reason), '');
    return;
  }
  const wc = d.getCurrentTabWebContents();
  if (v.decision === d.findGuard.FIND_SKIP_EMPTY) {
    d.findState = { text: '', matchCase: !!matchCase, wholeWord: !!wholeWord };
    if (wc) wc.stopFindInPage('clearSelection');
    return;
  }
  if (v.decision === d.findGuard.FIND_COALESCE) return;

  // 选项变化（区分大小写 / 整词）时重新开始查找，而不是沿用上一次的匹配位置。
  const optionsChanged = d.findState.matchCase !== v.matchCase || d.findState.wholeWord !== v.wholeWord;
  d.findState = { text: v.text, matchCase: v.matchCase, wholeWord: v.wholeWord };
  if (!wc) return;
  wc.findInPage(v.text, {
    forward: forward !== false,
    matchCase: v.matchCase,
    wholeWord: v.wholeWord,
    ...(optionsChanged ? { findNext: false } : {}),
  });
});

d.ipcMain.on('stop-find', (event) => {
  if (!d.isMainSender(event)) return;
  d.findState.text = '';
  // 结束查找时同时清掉去重指纹，允许用户重新打开查找栏查找同一个词。
  d.findGuard.resetFind(d.findRateState);
  const wc = d.getCurrentTabWebContents();
  if (wc) wc.stopFindInPage('clearSelection');
});

d.ipcMain.on('show-more-options-menu', (event, position) => {
  if (!d.isMainSender(event)) return;
  const menu = new d.Menu();
  const wc = d.getCurrentTabWebContents();
  const currentZoomLevel = wc ? wc.getZoomLevel() : 0;
  const currentZoomPercent = Math.round(Math.pow(1.2, currentZoomLevel) * 100);
  menu.append(new d.MenuItem({ label: `重置缩放 (当前: ${currentZoomPercent}%)`, click: d.resetZoom }));
  menu.append(new d.MenuItem({ label: '放大', click: d.zoomIn }));
  menu.append(new d.MenuItem({ label: '缩小', click: d.zoomOut }));
  menu.append(new d.MenuItem({ type: 'separator' }));
  menu.append(new d.MenuItem({
    label: '重新打开已关闭的标签页 (Ctrl+Shift+T)',
    click: () => {
      const lastClosedTab = d.getLastClosedTab();
      if (lastClosedTab) d.createNewTab(lastClosedTab.url);
    }
  }));
  menu.append(new d.MenuItem({ type: 'separator' }));
  menu.append(new d.MenuItem({
    label: '休眠所有后台标签页 (Ctrl+Shift+S)',
    enabled: d.memorySaverEnabled,
    click: () => {
      const n = d.discardAllBackgroundTabs();
      d.sendToRenderer('show-toast', n > 0 ? `已休眠 ${n} 个后台标签页` : '没有需要休眠的后台标签页');
    }
  }));
  const pos = position && Number.isFinite(position.x) && Number.isFinite(position.y)
    ? { x: Math.round(position.x), y: Math.round(position.y) }
    : null;
  menu.popup(pos ? { window: d.mainWindow, x: pos.x, y: pos.y } : { window: d.mainWindow });
});
}

function registerTabOverviewIpc() {
d.ipcMain.handle('tab-overview-snapshot', (event) => {
  if (!d.isTabOverviewFrameSender(event)) return { ok: false, error: 'denied' };
  return {
    ok: true,
    tabs: d.tabs.map(d.tabOverviewItem),
    groups: d.tabGroupModel.orderedGroupIds().map(gid => {
      const g = d.tabGroupModel.getGroup(gid);
      return {
        id: gid,
        name: g ? String(g.title || '') : '',
        color: g ? String(g.color || '') : '',
        collapsed: !!(g && g.collapsed),
      };
    }),
  };
});

// 概览页点击卡片：切到该标签。id 不存在时静默失败（标签可能已被关闭）。
d.ipcMain.handle('tab-overview-activate', (event, payload = {}) => {
  if (!d.isTabOverviewFrameSender(event)) return { ok: false, error: 'denied' };
  const id = payload && payload.id != null ? String(payload.id) : '';
  const index = d.tabs.findIndex(t => t && String(t.id) === id);
  if (index < 0) return { ok: false, error: 'not-found' };
  d.switchToTab(index);
  return { ok: true, id };
});

// 概览页关闭卡片：复用现有 closeTab（含分组联动 / 最近关闭 / 持久化）。
d.ipcMain.handle('tab-overview-close', (event, payload = {}) => {
  if (!d.isTabOverviewFrameSender(event)) return { ok: false, error: 'denied' };
  const id = payload && payload.id != null ? String(payload.id) : '';
  const index = d.tabs.findIndex(t => t && String(t.id) === id);
  if (index < 0) return { ok: false, error: 'not-found' };
  d.closeTab(index);
  return { ok: true, id };
});

// 概览页缩略图：capturePage 截当前标签画面，按最长边 ≤360px 缩放成 dataURL。
// 只接受概览页帧；视图已销毁 / 崩溃 / 后台被丢弃的标签返回空，不让单页拖垮整页。
d.ipcMain.handle('tab-overview-capture', async (event, payload = {}) => {
  if (!d.isTabOverviewFrameSender(event)) return { ok: false, error: 'denied' };
  const id = payload && payload.id != null ? String(payload.id) : '';
  const index = d.tabs.findIndex(t => t && String(t.id) === id);
  if (index < 0) return { ok: false, error: 'not-found' };
  const tab = d.tabs[index];
  const wc = tab && tab.view && tab.view.webContents;
  if (!wc || wc.isDestroyed() || tab.crashed || tab.discarded) {
    return { ok: false, error: 'unavailable' };
  }
  try {
    const image = await wc.capturePage();
    if (image.isEmpty()) return { ok: false, error: 'empty' };
    const size = image.getSize();
    const longest = Math.max(size.width, size.height) || 1;
    let scaled = image;
    if (longest > 360) {
      const factor = 360 / longest;
      scaled = image.resize({
        width: Math.max(1, Math.round(size.width * factor)),
        height: Math.max(1, Math.round(size.height * factor)),
      });
    }
    const dataUrl = scaled.toDataURL();
    if (typeof dataUrl !== 'string' || dataUrl.length > 600000) {
      return { ok: false, error: 'too-large' };
    }
    return { ok: true, dataUrl };
  } catch {
    return { ok: false, error: 'capture-failed' };
  }
});
}

function registerExtensionIpc() {
d.ipcMain.handle('add-extension', async (event, folderPath) => {
  if (!d.isMainSender(event)) return { success: false, error: 'Unauthorized' };
  try {
    const validation = await d.validateExtensionFolder(folderPath);
    if (!validation.valid) return { success: false, error: validation.error };
    const { manifest } = validation;
    const extensionId = d.extensionStore.buildExtensionId(manifest.name, manifest.version);
    if (!extensionId) return { success: false, error: '插件名称或版本不合法，无法生成安全ID' };
    const config = await d.readExtensionsConfig();
    if (config.extensions.find(ext => ext.id === extensionId)) return { success: false, error: '该插件已存在' };
    const copyResult = await d.copyExtensionToStorage(folderPath, extensionId);
    if (!copyResult.ok) return { success: false, error: '复制插件文件失败（' + copyResult.reason + '）' };
    let iconPath = '';
    if (manifest.icons) {
      const iconSizes = Object.keys(manifest.icons).sort((a, b) => parseInt(b) - parseInt(a));
      if (iconSizes.length > 0) {
        const iconName = manifest.icons[iconSizes[0]];
        if (d.isSafeEntryName(iconName)) {
          iconPath = d.extensionStore.resolveWithinRoot(d.extensionsPath, extensionId, iconName) || '';
        }
      }
    }
    const extensionDir = d.extensionStore.resolveExtensionDir(d.extensionsPath, extensionId);
    const newExtension = {
      id: extensionId, name: manifest.name, version: manifest.version,
      description: manifest.description || '', icon: iconPath,
      path: extensionDir || '', enabled: true, addedDate: new Date().toISOString()
    };
    config.extensions.push(newExtension);
    const saveSuccess = await d.saveExtensionsConfig(config);
    if (!saveSuccess) return { success: false, error: '保存配置失败' };
    return { success: true, extension: newExtension };
  } catch (e) { return { success: false, error: e.message }; }
});

d.ipcMain.handle('get-extensions', async (event) => {
  if (!d.isMainSender(event)) return { success: false, error: 'Unauthorized', extensions: [] };
  try {
    const config = await d.readExtensionsConfig();
    return { success: true, extensions: config.extensions };
  } catch (e) { return { success: false, error: e.message, extensions: [] }; }
});

d.ipcMain.handle('toggle-extension', async (event, { id, enabled }) => {
  if (!d.isMainSender(event)) return { success: false, error: 'Unauthorized' };
  try {
    const config = await d.readExtensionsConfig();
    const extension = config.extensions.find(ext => ext.id === id);
    if (!extension) return { success: false, error: '插件未找到' };
    extension.enabled = enabled;
    const saveSuccess = await d.saveExtensionsConfig(config);
    if (!saveSuccess) return { success: false, error: '保存配置失败' };
    return { success: true };
  } catch (e) { return { success: false, error: e.message }; }
});

d.ipcMain.handle('remove-extension', async (event, id) => {
  if (!d.isMainSender(event)) return { success: false, error: 'Unauthorized' };
  try {
    const config = await d.readExtensionsConfig();
    const extensionIndex = config.extensions.findIndex(ext => ext.id === id);
    if (extensionIndex === -1) return { success: false, error: '插件未找到' };
    await d.unloadExtension(id);
    // 递归 rm 前必须把目录收口到扩展根之内：配置若被塞成 id="../AppData"，旧实现
    // path.join 后会递归删除扩展目录之外的内容。越界直接拒绝删除。
    const extensionPath = d.extensionStore.resolveExtensionDir(d.extensionsPath, id);
    if (!extensionPath) {
      d.recordSecurityEvent('extension-blocked', 'warn',
        `拒绝删除越界插件目录（id=${id}）`, '');
      return { success: false, error: '插件目录不合法' };
    }
    if (d.fsSync.existsSync(extensionPath)) await d.fs.rm(extensionPath, { recursive: true, force: true });
    config.extensions.splice(extensionIndex, 1);
    const saveSuccess = await d.saveExtensionsConfig(config);
    if (!saveSuccess) return { success: false, error: '保存配置失败' };
    return { success: true };
  } catch (e) { return { success: false, error: e.message }; }
});

d.ipcMain.handle('browse-folder', async (event) => {
  if (!d.isMainSender(event)) return { success: false, error: 'Unauthorized' };
  try {
    const result = await d.dialog.showOpenDialog(d.mainWindow, { title: '选择插件文件夹', properties: ['openDirectory'] });
    if (!result.canceled && result.filePaths.length > 0) return { success: true, path: result.filePaths[0] };
    return { success: false, error: '用户取消选择' };
  } catch (e) { return { success: false, error: e.message }; }
});

d.ipcMain.on('show-context-menu', (event, data) => {
  if (!d.isMainSender(event)) return;
  const payload = data && typeof data === 'object' ? data : {};
  const menuType = payload.menuType === 'selection' ? 'selection' : 'default';
  const selectedText = typeof payload.selectedText === 'string' ? payload.selectedText.slice(0, 256) : '';
  const menu = d.createContextMenu(menuType, selectedText);
  if (!d.mainWindow || d.mainWindow.isDestroyed()) return;
  menu.popup({ window: d.mainWindow });
});

// ===== 标签页右键菜单（原生 Tab 菜单）=====
// 渲染层在标签元素上右键时只上报内部 tabId；这里基于主进程维护的 tab 状态构建
// 原生菜单。菜单项的 URL / 标题全部来自本机 tabs 数据（非网页注入），复制走
// clipboard 仅写入受控文本，杜绝自绘菜单的样式/事件注入面。
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

function registerCertificateIpc() {
d.ipcMain.handle('history-snapshot', (event) => {
  if (!d.isHistoryFrameSender(event)) return { ok: false, error: 'denied', items: [] };
  const items = d.history.slice(0, d.MAX_HISTORY_ENTRIES).map(item => ({
    url: typeof item.url === 'string' ? item.url.slice(0, 8192) : '',
    title: typeof item.title === 'string' ? item.title.slice(0, 300) : '',
    timestamp: typeof item.timestamp === 'number' && Number.isFinite(item.timestamp) ? item.timestamp : 0,
  }));
  return { ok: true, items };
});

// 历史页删除单条：按 url + timestamp 精确匹配删除（同一 URL 可能有多条时间戳）。
// 匹配不到静默成功；删除后落盘。
d.ipcMain.handle('history-delete-entry', (event, payload = {}) => {
  if (!d.isHistoryFrameSender(event)) return { ok: false, error: 'denied' };
  const url = typeof payload.url === 'string' ? payload.url : '';
  const timestamp = typeof payload.timestamp === 'number' ? payload.timestamp : NaN;
  const before = d.history.length;
  d.history = d.history.filter(item =>
    !(String(item.url || '') === url && item.timestamp === timestamp));
  if (d.history.length !== before) d.saveHistory();
  return { ok: true, removed: before - d.history.length };
});

// 历史页点击条目：经 isSafeUrl 校验后在当前窗口新开标签。cosy:// 内置地址
// 同样放行（历史页“在新标签打开”允许内部页跳转），其余非法协议一律拒绝。
d.ipcMain.handle('history-open-url', (event, url) =>
  d.openUrlFromInternalFrame(d.isHistoryFrameSender(event), url));

// 历史页清空：仅受信帧可触发，与面板“清除历史”共用 saveHistory 落盘。
d.ipcMain.handle('history-clear-all', (event) => {
  if (!d.isHistoryFrameSender(event)) return { ok: false, error: 'denied' };
  d.history = [];
  d.saveHistory();
  return { ok: true };
});

// 历史页批量删除：urls 数组（每项 {url,timestamp}）逐条精确匹配。
// 条数上限防滥用；删除后落盘。
d.ipcMain.handle('history-delete-entries', (event, payload = {}) => {
  if (!d.isHistoryFrameSender(event)) return { ok: false, error: 'denied' };
  const urls = Array.isArray(payload.urls) ? payload.urls : [];
  if (urls.length > 5000) return { ok: false, error: 'too-many' };
  const targets = [];
  for (const it of urls) {
    if (!it || typeof it !== 'object') continue;
    const url = typeof it.url === 'string' ? it.url.slice(0, 8192) : '';
    const timestamp = typeof it.timestamp === 'number' ? it.timestamp : NaN;
    if (!url || !Number.isFinite(timestamp)) continue;
    targets.push({ url, timestamp });
  }
  if (targets.length === 0) return { ok: true, removed: 0 };
  const before = d.history.length;
  d.history = d.history.filter(item => {
    for (const t of targets) {
      if (String(item.url || '') === t.url && item.timestamp === t.timestamp) return false;
    }
    return true;
  });
  if (d.history.length !== before) d.saveHistory();
  return { ok: true, removed: before - d.history.length };
});

// 历史页导出 JSON：弹保存框，写 UTF-8 文件。内容由渲染层传入的纯文本
// （已本地生成），本端仅做类型与长度收口，防止大 payload 撑爆内存。
d.ipcMain.handle('history-export-json', async (event, payload = {}) => {
  if (!d.isHistoryFrameSender(event)) return { ok: false, error: 'denied' };
  try {
    const name = typeof payload.name === 'string' ? payload.name.slice(0, 128).replace(/[^\w.-]/g, '') : 'opencosy-history.json';
    const text = typeof payload.text === 'string' ? payload.text : '';
    if (text.length > 64 * 1024 * 1024) return { ok: false, error: 'too-large' };
    const result = await d.dialog.showSaveDialog(d.mainWindow, {
      title: '导出历史记录',
      defaultPath: name,
      filters: [{ name: 'JSON 文件', extensions: ['json'] }, { name: '所有文件', extensions: ['*'] }],
    });
    if (result.canceled || !result.filePath) return { ok: true, canceled: true };
    d.fsSync.writeFileSync(result.filePath, text, 'utf-8');
    return { ok: true, path: result.filePath, bytes: Buffer.byteLength(text, 'utf-8') };
  } catch (e) {
    console.error('导出历史失败:', e);
    return { ok: false, error: e.message };
  }
});

// 书签管理器快照：返回全量书签（拷贝防外部篡改，标题/URL 长度收口）。
d.ipcMain.handle('bookmarks-snapshot', (event) => {
  if (!d.isBookmarksFrameSender(event)) return { ok: false, error: 'denied', items: [] };
  const items = d.bookmarks.map(d.sanitizeBookmarkLike);
  return { ok: true, items };
});

// 书签管理器打开：经 isSafeUrl 校验（含 cosy:// 内部页），新标签打开。
d.ipcMain.handle('bookmarks-open-url', (event, url) =>
  d.openUrlFromInternalFrame(d.isBookmarksFrameSender(event), url));

// 书签管理器删除：按 url 精确匹配，删除后落盘并广播（书签栏同步）。
d.ipcMain.handle('bookmarks-remove', (event, payload = {}) => {
  if (!d.isBookmarksFrameSender(event)) return { ok: false, error: 'denied' };
  const url = typeof payload.url === 'string' ? payload.url : '';
  const before = d.bookmarks.length;
  d.bookmarks = d.bookmarks.filter(b => !(String(b.url || '') === url));
  if (d.bookmarks.length !== before) {
    d.saveBookmarks();
    d.sendToRenderer('bookmarks-updated', d.bookmarks);
  }
  return { ok: true, removed: before - d.bookmarks.length };
});

// 书签管理器重命名：标题经 300 字收口 + 控制字符清洗，防注入脏文本。
d.ipcMain.handle('bookmarks-rename', (event, payload = {}) => {
  if (!d.isBookmarksFrameSender(event)) return { ok: false, error: 'denied' };
  const url = typeof payload.url === 'string' ? payload.url : '';
  let title = typeof payload.title === 'string' ? payload.title : '';
  title = title.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 300).trim();
  if (!title) return { ok: false, error: 'bad-title' };
  const b = d.bookmarks.find(x => String(x.url || '') === url);
  if (!b) return { ok: false, error: 'not-found' };
  b.title = title;
  d.saveBookmarks();
  d.sendToRenderer('bookmarks-updated', d.bookmarks);
  return { ok: true, title };
});

// 稍后读快照：返回全量条目（拷贝防外部篡改，标题/URL 长度收口，与书签同款净化）。
d.ipcMain.handle('readinglist-snapshot', (event) => {
  if (!d.isReadingListFrameSender(event)) return { ok: false, error: 'denied', items: [] };
  const items = d.readingList.map(d.sanitizeBookmarkLike);
  return { ok: true, items };
});
}

module.exports = { bindDeps, registerFindIpc, registerTabOverviewIpc, registerExtensionIpc, registerCertificateIpc };
