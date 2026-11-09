'use strict';
function registerDownloadShelf(d) {
d.ipcMain.on('save-settings', (event, settings) => {
  if (!d.isMainSender(event)) return;
  // r33：settings 是“整包序列化落盘”通道，先用 inputGuard 做形状与体量裁决：
  // 非普通对象 / 嵌套过深 / 键数过多 / 体量逼近磁盘上限（16MiB）一律拒绝，防止
  // 被攻陷渲染层用深层巨型对象打爆内存与 cosySettings.json。
  const objRes = d.inputGuard.asPlainObject(settings);
  if (!objRes.ok) {
    d.recordSecurityEvent('ipc-input-rejected', 'warn',
      'save-settings 收到非普通对象入参，已拒绝', d.originOfContents(event.sender));
    event.reply('settings-saved', { success: false, error: 'invalid settings payload' });
    return;
  }
  const measure = d.inputGuard.measureObject(settings);
  if (!measure.ok) {
    d.recordSecurityEvent('ipc-input-rejected', 'warn',
      `save-settings 整包体量异常已拒绝（${measure.reason}，keys=${measure.keys}，bytes=${measure.bytes}）`,
      d.originOfContents(event.sender));
    event.reply('settings-saved', { success: false, error: 'settings payload too large' });
    return;
  }
  try {
    const clean = d.sanitizeSettings(settings);
    const settingsPath = d.path.join(d.app.getPath('userData'), 'cosySettings.json');
    // 崩溃安全原子写：避免写一半断电导致设置文件截断、下次启动全部偏好丢失。
    d.ledgerStore.writeJSONStore(settingsPath, clean, { pretty: true });
    // 立即把 darkMode / httpsOnly / memorySaver 应用到运行时
    d.applyDarkMode(clean.darkMode);
    d.httpsOnlyEnabled = clean.httpsOnly !== false;
    d.bookmarkBarVisible = clean.bookmarkBarVisible !== false;
    d.blockTrackers = clean.blockTrackers !== false;
    d.blockThirdPartyCookies = clean.blockThirdPartyCookies !== false;
    d.hardenCookies = clean.hardenCookies !== false;
    d.blockLocalNetworkAccess = clean.blockLocalNetworkAccess !== false;
    d.reduceClientHints = clean.reduceClientHints !== false;
    d.blockAdSignals = clean.blockAdSignals !== false;
    d.blockHyperlinkPing = clean.blockHyperlinkPing !== false;
    d.stripAcceptCh = clean.stripAcceptCh !== false;
    if ('allowPictureInPicture' in clean) d.allowPictureInPicture = !!clean.allowPictureInPicture;
    if ('searchEngine' in clean) d.searchProviderId = d.searchProvider.sanitizeProviderChoice(clean.searchEngine);
    if ('webrtcMode' in clean) d.webrtcMode = d.fpGuard.normalizeWebRtcMode(clean.webrtcMode);
    d.applyWebRtcPolicy();
    if ('dohMode' in clean) d.dohMode = d.dohGuard.normalizeMode(clean.dohMode);
    if ('dohProvider' in clean) d.dohProvider = clean.dohProvider;
    if ('dohCustomUrl' in clean) d.dohCustomUrl = clean.dohCustomUrl;
    d.applySecureDns();
    d.crashRecoveryEnabled = clean.crashRecovery !== false;
    d.stripTrackingParams = clean.stripTrackingParams !== false;
    if ('memorySaver' in clean) d.memorySaverEnabled = !!clean.memorySaver;
    if ('clearOnExit' in clean) d.clearOnExit = !!clean.clearOnExit;
    if ('confirmCloseMultiple' in clean) d.confirmCloseMultiple = !!clean.confirmCloseMultiple;
    if ('spellcheckEnabled' in clean) d.spellcheckEnabled = !!clean.spellcheckEnabled;
    if ('spellcheckLanguages' in clean) d.spellcheckLanguages = d.sanitizeSpellcheckLanguages(clean.spellcheckLanguages);
    if ('downloadMaxBytes' in clean) d.downloadMaxBytes = d.downloadSizeGuard.normalizeLimit(clean.downloadMaxBytes);
    d.applySpellcheckSettings();
    event.reply('settings-saved', { success: true });
  } catch (e) {
    console.error('保存设置失败:', e);
    event.reply('settings-saved', { success: false, error: e.message });
  }
});

d.ipcMain.on('update-theme-color', (event, color) => {
  if (!d.isMainSender(event)) return;
  if (!d.isValidColor(color)) return;
  d.sendToRenderer('update-theme-color', color);
  d.tabs.forEach(tab => {
    if (tab.view?.webContents) tab.view.webContents.send('update-theme-color', color);
  });
});

d.ipcMain.on('get-settings', (event) => {
  if (!d.isMainSender(event)) return;
  try {
    // 复用统一的有界设置读取，坏 / 超大文件回落 {}，不再 existsSync+整读。
    event.reply('settings-loaded', d.readStoredSettings());
  } catch (e) {
    console.error('读取设置失败:', e);
    event.reply('settings-loaded', {});
  }
});

// get-spellcheck-info 返回拼写检查当前状态与平台实际可用的语言列表，
// 设置页据此隐藏当前系统没有词典的语言，避免用户勾了一个永远不生效的选项。
d.ipcMain.handle('get-spellcheck-info', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  let available = [];
  try {
    available = d.session.defaultSession.availableSpellCheckerLanguages || [];
  } catch (e) {
    console.error('读取可用拼写语言失败:', e);
  }
  const availableSet = new Set(available);
  return {
    success: true,
    enabled: d.spellcheckEnabled,
    languages: d.spellcheckLanguages,
    selectable: d.ALLOWED_SPELLCHECK_LANGUAGES.filter(l => availableSet.has(l))
  };
});

d.ipcMain.on('export-config', async (event, content) => {
  if (!d.isMainSender(event)) return;
  try {
    const result = await d.dialog.showSaveDialog(d.mainWindow, {
      title: '导出配置', defaultPath: 'cosy_config.inf',
      filters: [{ name: '配置文件', extensions: ['inf'] }, { name: '所有文件', extensions: ['*'] }]
    });
    if (!result.canceled && result.filePath) {
      d.fsSync.writeFileSync(result.filePath, content, 'utf-8');
      event.reply('export-config-success', '配置文件导出成功！');
    } else {
      event.reply('export-config-canceled', '导出操作已取消');
    }
  } catch (e) {
    console.error('导出配置失败:', e);
    event.reply('export-config-error', '导出配置失败: ' + e.message);
  }
});

d.ipcMain.handle('get-bookmarks', (event) => {
  if (!d.isMainSender(event)) return { success: false, bookmarks: [] };
  return { success: true, bookmarks: d.bookmarksks };
});

// 导出书签：format=json 导 OpenCosy 自有 JSON，html 导 Netscape 格式
// （可直接被 Chrome / Edge / Firefox 导入）。
d.ipcMain.handle('export-bookmarks', async (event, format) => {
  if (!d.isMainSender(event)) return { success: false, error: '无权操作' };
  try {
    const useHTML = format === 'html';
    const stamp = new Date().toISOString().slice(0, 10);
    const result = await d.dialog.showSaveDialog(d.mainWindow, {
      title: '导出书签',
      defaultPath: useHTML ? `opencosy-bookmarks-${stamp}.html` : `opencosy-bookmarks-${stamp}.json`,
      filters: useHTML
        ? [{ name: 'Netscape 书签 HTML', extensions: ['html'] }, { name: '所有文件', extensions: ['*'] }]
        : [{ name: 'JSON 书签文件', extensions: ['json'] }, { name: '所有文件', extensions: ['*'] }],
    });
    if (result.canceled || !result.filePath) return { success: false, canceled: true };
    const content = useHTML ? d.bookmarkIO.buildExportHTML(d.bookmarks) : d.bookmarkIO.buildExportJSON(d.bookmarks);
    d.fsSync.writeFileSync(result.filePath, content, 'utf-8');
    return { success: true, count: d.bookmarks.length, format: useHTML ? 'html' : 'json' };
  } catch (e) {
    console.error('导出书签失败:', e);
    return { success: false, error: e.message };
  }
});

// 导入书签：弹原生选择框，按内容自动识别 JSON / Netscape HTML，
// 严格校验后合并去重落盘。整个解析发生在主进程，渲染层只拿到统计结果。
d.ipcMain.handle('import-bookmarks', async (event) => {
  if (!d.isMainSender(event)) return { success: false, error: '无权操作' };
  try {
    const result = await d.dialog.showOpenDialog(d.mainWindow, {
      title: '导入书签',
      properties: ['openFile'],
      filters: [
        { name: '书签文件', extensions: ['html', 'htm', 'json'] },
        { name: '所有文件', extensions: ['*'] },
      ],
    });
    if (result.canceled || !result.filePaths || result.filePaths.length === 0) {
      return { success: false, canceled: true };
    }
    const filePath = result.filePaths[0];
    const stat = d.fsSync.statSync(filePath);
    if (stat.size > d.bookmarkIO.MAX_IMPORT_FILE_BYTES) {
      return { success: false, error: '书签文件过大（上限 8MiB）' };
    }
    const buffer = d.fsSync.readFileSync(filePath);
    const { format: detectedFormat, bookmarks: incoming } = d.bookmarkIO.parseBookmarkFile(buffer);
    const before = d.bookmarks.length;
    const { merged, added } = d.bookmarkIO.mergeBookmarks(d.bookmarks, incoming);
    if (added === 0) {
      return { success: true, added: 0, total: before, format: detectedFormat, duplicated: incoming.length };
    }
    d.bookmarks = merged;
    d.saveBookmarks();
    d.sendToRenderer('bookmarks-updated', d.bookmarks);
    return { success: true, added, total: d.bookmarks.length, format: detectedFormat };
  } catch (e) {
    console.error('导入书签失败:', e);
    return { success: false, error: e.message };
  }
});

d.ipcMain.handle('get-history', (event) => {
  if (!d.isMainSender(event)) return { success: false, history: [] };
  return { success: true, history: d.history.slice(0, 100) };
});

d.ipcMain.handle('clear-history', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  d.history = [];
  d.saveHistory();
  return { success: true };
});
}

module.exports = { registerDownloadShelf };
