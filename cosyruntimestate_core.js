'use strict';

const { registerRuntimeTabsIpc } = require('./cosyruntimetabsipc_core');

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

  registerRuntimeTabsIpc(d);
}

module.exports = { bindDeps, bootstrapRuntimeState };
