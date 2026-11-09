'use strict';

let d = {};

function bindDeps(x) {
  d = x;
}

function bootstrapRuntimeState() {
d.cosytabsmainMod.bindDeps({ get pinModel() { return d.pinModel; }, set pinModel(v) { d.pinModel = v; }, get tabs() { return d.tabs; }, set tabs(v) { d.tabs = v; }, get ledgerStore() { return d.ledgerStore; }, set ledgerStore(v) { d.ledgerStore = v; }, get pinStorePath() { return d.pinStorePath; }, set pinStorePath(v) { d.pinStorePath = v; }, get pinSaveTimer() { return d.pinSaveTimer; }, set pinSaveTimer(v) { d.pinSaveTimer = v; }, get pinTabs() { return d.pinTabs; }, set pinTabs(v) { d.pinTabs = v; }, get fsSync() { return d.fsSync; }, set fsSync(v) { d.fsSync = v; }, get sendToRenderer() { return d.sendToRenderer; }, set sendToRenderer(v) { d.sendToRenderer = v; }, get currentTabIndex() { return d.currentTabIndex; }, set currentTabIndex(v) { d.currentTabIndex = v; }, get getUrlProtocol() { return d.getUrlProtocol; }, set getUrlProtocol(v) { d.getUrlProtocol = v; }, get isSafeUrl() { return d.isSafeUrl; }, set isSafeUrl(v) { d.isSafeUrl = v; }, get createNewTab() { return d.createNewTab; }, set createNewTab(v) { d.createNewTab = v; }, get closeTab() { return d.closeTab; }, set closeTab(v) { d.closeTab = v; }, get loadStoredTabGroups() { return d.loadStoredTabGroups; }, set loadStoredTabGroups(v) { d.loadStoredTabGroups = v; }, get tabGroups() { return d.tabGroups; }, set tabGroups(v) { d.tabGroups = v; }, get tabGroupModel() { return d.tabGroupModel; }, set tabGroupModel(v) { d.tabGroupModel = v; }, get applyTabGroupArrangement() { return d.applyTabGroupArrangement; }, set applyTabGroupArrangement(v) { d.applyTabGroupArrangement = v; }, get broadcastTabGroups() { return d.broadcastTabGroups; }, set broadcastTabGroups(v) { d.broadcastTabGroups = v; }, get dloadGuard() { return d.dloadGuard; }, set dloadGuard(v) { d.dloadGuard = v; }, get downloadName() { return d.downloadName; }, set downloadName(v) { d.downloadName = v; }, get recordSecurityEvent() { return d.recordSecurityEvent; }, set recordSecurityEvent(v) { d.recordSecurityEvent = v; }, get downloadPathCollision() { return d.downloadPathCollision; }, set downloadPathCollision(v) { d.downloadPathCollision = v; }, get downloadOriginByPath() { return d.downloadOriginByPath; }, set downloadOriginByPath(v) { d.downloadOriginByPath = v; }, get MAX_DOWNLOAD_ORIGIN_ENTRIES() { return d.MAX_DOWNLOAD_ORIGIN_ENTRIES; }, set MAX_DOWNLOAD_ORIGIN_ENTRIES(v) { d.MAX_DOWNLOAD_ORIGIN_ENTRIES = v; }, get downloadRiskSaveTimer() { return d.downloadRiskSaveTimer; }, set downloadRiskSaveTimer(v) { d.downloadRiskSaveTimer = v; }, get downloadRiskStorePath() { return d.downloadRiskStorePath; }, set downloadRiskStorePath(v) { d.downloadRiskStorePath = v; }, get downloadRiskRecords() { return d.downloadRiskRecords; }, set downloadRiskRecords(v) { d.downloadRiskRecords = v; }, get loadDownloadRisks() { return d.loadDownloadRisks; }, set loadDownloadRisks(v) { d.loadDownloadRisks = v; }, get MAX_DOWNLOAD_RISK_RECORDS() { return d.MAX_DOWNLOAD_RISK_RECORDS; }, set MAX_DOWNLOAD_RISK_RECORDS(v) { d.MAX_DOWNLOAD_RISK_RECORDS = v; }, get handleDownloadEventCtx() { return d.handleDownloadEventCtx; }, set handleDownloadEventCtx(v) { d.handleDownloadEventCtx = v; }, get webContents() { return d.webContents; }, set webContents(v) { d.webContents = v; }, get managedDownloadSessions() { return d.managedDownloadSessions; }, set managedDownloadSessions(v) { d.managedDownloadSessions = v; }, get session() { return d.session; }, set session(v) { d.session = v; }, get pathToFileURL() { return d.pathToFileURL; }, set pathToFileURL(v) { d.pathToFileURL = v; }, get deeplinkGuard() { return d.deeplinkGuard; }, set deeplinkGuard(v) { d.deeplinkGuard = v; }, get getCurrentTabWebContents() { return d.getCurrentTabWebContents; }, set getCurrentTabWebContents(v) { d.getCurrentTabWebContents = v; }, get findState() { return d.findState; }, set findState(v) { d.findState = v; }, get Menu() { return d.Menu; }, set Menu(v) { d.Menu = v; }, get MenuItem() { return d.MenuItem; }, set MenuItem(v) { d.MenuItem = v; }, get mainWindow() { return d.mainWindow; }, set mainWindow(v) { d.mainWindow = v; }, get goHome() { return d.goHome; }, set goHome(v) { d.goHome = v; }, get isDev() { return d.isDev; }, set isDev(v) { d.isDev = v; }, get toggleDevTools() { return d.toggleDevTools; }, set toggleDevTools(v) { d.toggleDevTools = v; }, get ALLOWED_SETTING_KEYS() { return d.ALLOWED_SETTING_KEYS; }, set ALLOWED_SETTING_KEYS(v) { d.ALLOWED_SETTING_KEYS = v; }, get readingList() { return d.readingList; }, set readingList(v) { d.readingList = v; }, get saveReadingList() { return d.saveReadingList; }, set saveReadingList(v) { d.saveReadingList = v; }, get customRules() { return d.customRules; }, set customRules(v) { d.customRules = v; }, get blockRules() { return d.blockRules; }, set blockRules(v) { d.blockRules = v; }, get urlResolve() { return d.urlResolve; }, set urlResolve(v) { d.urlResolve = v; } });

d.app.whenReady().then(async () => {
  d.loadHistory();
  d.loadBookmarks();
  d.loadReadingList();
  d.loadZoomFactors();
  d.loadCustomRulesFromDisk(d.path.join(d.app.getPath('userData'), 'blockrules.json'));
  d.initVaultOnStartup();
  d.loadDownloads();

  // 启动时还原 darkMode / httpsOnly / memorySaver 等运行时状态
  const stored = d.readStoredSettings();
  d.applyDarkMode(!!stored.darkMode);
  d.httpsOnlyEnabled = stored.httpsOnly !== false;
  d.bookmarkBarVisible = stored.bookmarkBarVisible !== false;
  d.loadHttpsExceptions();
  d.blockTrackers = stored.blockTrackers !== false;
  d.blockThirdPartyCookies = stored.blockThirdPartyCookies !== false;
  d.hardenCookies = stored.hardenCookies !== false;
  d.blockLocalNetworkAccess = stored.blockLocalNetworkAccess !== false;
  d.reduceClientHints = stored.reduceClientHints !== false;
  d.blockAdSignals = stored.blockAdSignals !== false;
  d.blockHyperlinkPing = stored.blockHyperlinkPing !== false;
  d.stripAcceptCh = stored.stripAcceptCh !== false;
  if ('allowPictureInPicture' in stored) d.allowPictureInPicture = !!stored.allowPictureInPicture;
  if ('webrtcMode' in stored) d.webrtcMode = d.fpGuard.normalizeWebRtcMode(stored.webrtcMode);
  d.dohMode = d.dohGuard.normalizeMode(stored.dohMode);
  if (typeof stored.dohProvider === 'string') d.dohProvider = stored.dohProvider;
  if (typeof stored.dohCustomUrl === 'string') d.dohCustomUrl = stored.dohCustomUrl;
  d.crashRecoveryEnabled = stored.crashRecovery !== false;
  d.stripTrackingParams = stored.stripTrackingParams !== false;
  if ('memorySaver' in stored) d.memorySaverEnabled = !!stored.memorySaver;
  if ('clearOnExit' in stored) d.clearOnExit = !!stored.clearOnExit;
  if ('confirmCloseMultiple' in stored) d.confirmCloseMultiple = !!stored.confirmCloseMultiple;
  d.startMemorySaver();

  if (process.platform === 'win32') d.app.setAsDefaultProtocolClient('cosy');

  d.protocol.registerFileProtocol('cosy', (request, callback) => {
    try {
      // host 白名单映射，path/query 一律不参与文件选择，杜绝 cosy: 路径穿越。
      const r = d.cosyScheme.resolveCosyFilePath(request.url, d.path.join(__dirname, 'src'));
      callback({ path: r.absolutePath });
    } catch (e) {
      console.error('注册cosy协议失败:', e);
      callback({ path: d.path.join(__dirname, 'src', 'newtab.html') });
    }
  });

  d.protocol.registerFileProtocol('file', (request, callback) => {
    try {
      // 用 WHATWG URL + fileURLToPath 归一，拒绝 file://server/share 远程/UNC host，
      // 并把可读路径严格收敛进 getSafeDirs() 允许目录。
      const verdict = d.cosyScheme.resolveAllowedFileUrl(request.url, d.getSafeDirs());
      if (verdict.ok) {
        callback({ path: verdict.path });
      } else {
        if (verdict.reason === 'remote-host') {
          d.recordSecurityEvent('file-remote-blocked', 'warn',
            '拒绝经 file: 协议访问远程/UNC 主机', request.url);
        }
        callback({ error: -3 });
      }
    } catch (e) {
      console.error('注册file协议失败:', e);
      callback({ error: -3 });
    }
  });

  d.setupPermissionHandlers();
  d.setupSecurityHeaders();
  // r34：注册 app 级 GPU/无障碍系统事件守卫，并为后续 fromPartition 新会话补齐默认
  // 拒绝权限/设备策略与出向隐私头（须在 defaultSession 加固之后，靠去重跳过默认会话）。
  d.setupSystemEventGuards();
  d.setupExtraSessionHardening();

  // 启动期解析到的降硬开关在 ready 前只能写 stderr；安全事件存储就绪后补登一条聚合
  // 记录，方便在安全页面板排查被篡改的快捷方式/启动器（critical 的已直接退出，到不了这）。
  if (d.launchSwitchAudit.warnFlags.length > 0) {
    const desc = d.launchSwitchAudit.warnFlags
      .map(f => `${f.flag.raw}(${f.source})`)
      .join(', ');
    d.recordSecurityEvent('launch-switch-warn', 'warn',
      `检测到 ${d.launchSwitchAudit.warnFlags.length} 个降硬启动开关：${desc}`, '');
  }
  d.applyWebRtcPolicy();
  d.applySecureDns();
  d.setupDownloadManager();
  d.setupGlobalWebContentsHooks();
  d.setupNetworkAuth();
  d.setupNetworkStatus();
  // 拼写检查开关与语言在首个页面加载前就按持久化设置生效。
  const persisted = d.readPersistedSettings();
  d.spellcheckEnabled = persisted.spellcheckEnabled !== false;
  d.spellcheckLanguages = d.sanitizeSpellcheckLanguages(persisted.spellcheckLanguages);
  d.downloadMaxBytes = d.downloadSizeGuard.normalizeLimit(persisted.downloadMaxBytes);
  d.applySpellcheckSettings();
  d.searchProviderId = d.searchProvider.sanitizeProviderChoice(persisted.searchEngine);
  d.loadUaPolicyStateFromDisk();
  d.applyUaPolicyToSession(d.session.defaultSession);
  d.createWindow();
  await d.loadEnabledExtensions();

  d.app.on('activate', () => {
    if (d.BrowserWindow.getAllWindows().length === 0) d.createWindow();
  });
});

d.app.on('open-url', (event, url) => {
  event.preventDefault();
  // macOS 深链统一走 deeplinkguard：http(s) 严格解析，cosy: 主机必须白名单。
  const target = d.resolveStartupDeepLink(url, 'open-url');
  if (!target) return;
  if (!d.mainWindow || d.mainWindow.isDestroyed()) d.createWindow();
  setTimeout(() => {
    if (target.startsWith('cosy://') || target.startsWith('http://') || target.startsWith('https://')) {
      d.createNewTab(target);
    }
  }, 100);
});

d.app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') d.app.quit();
});

// child-process-gone 覆盖 GPU / utility / network 等非渲染子进程。
// Electron 通常会自动重启 GPU 进程，这里只记录并在异常退出（非正常清理）时
// 通知用户可能出现花屏/视频解码失效，提示重载标签，而不是静默吞掉。
d.app.on('child-process-gone', (event, details) => {
  console.error('子进程退出:', details?.type, details?.reason, details?.exitCode);
  try {
    if (d.mainWindow && !d.mainWindow.isDestroyed() && details?.reason !== 'clean-exit') {
      d.sendToRenderer('show-toast',
        `浏览器${details?.type || ''}进程异常（${details?.reason || 'unknown'}），如页面显示异常请按 Ctrl+R 重载`);
    }
  } catch {}
});

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

module.exports = { bindDeps, bootstrapRuntimeState };
