const { app, BrowserWindow, WebContentsView, ipcMain, session, protocol, Menu, MenuItem, dialog, shell, globalShortcut, clipboard, net, nativeTheme } = require('electron');
const path = require('path');
const fs = require('fs').promises;
const fsSync = require('fs');
const os = require('os');

let mainWindow;
let tabs = [];
let currentTabIndex = 0;
let fileToOpen = null;
let downloads = [];
let currentDownloadInfo = null;
let isTabBarCollapsed = false;
let bookmarks = [];
let history = [];
let recentlyClosedTabs = [];
const MAX_RECENTLY_CLOSED = 10;

// httpsOnlyEnabled 是运行时开关，默认 true；用户可以在设置里关掉。
// onBeforeRequest 据此决定是否把 http:// 升级成 https://。
let httpsOnlyEnabled = true;

const ALLOWED_PROTOCOLS = new Set(['http:', 'https:', 'file:', 'cosy:']);
const MAX_HISTORY_ENTRIES = 1000;
const DEFAULT_WINDOW_WIDTH = 1200;
const DEFAULT_WINDOW_HEIGHT = 800;
const MIN_WINDOW_WIDTH = 800;
const MIN_WINDOW_HEIGHT = 600;
const DEFAULT_TAB_BAR_HEIGHT_HORIZONTAL = 116;
const DEFAULT_TAB_BAR_WIDTH_VERTICAL = 200;
const COLLAPSED_TAB_BAR_WIDTH = 50;
const ZOOM_STEP = 0.5;
const SPELLCHECK_LANGUAGES = ['en-US', 'zh-CN'];

const isDev = !app.isPackaged;

function isMainSender(event) {
  return event.sender === mainWindow?.webContents;
}

function sendToRenderer(channel, ...args) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, ...args);
  }
}

function getSafeDirs() {
  return [
    app.getPath('downloads'), app.getPath('documents'),
    app.getPath('desktop'), app.getPath('pictures'),
    app.getPath('videos'), app.getPath('music'), __dirname,
  ];
}

function isInSafeDirs(filePath) {
  return getSafeDirs().some(dir => isPathInDir(filePath, dir));
}

class Tab {
  constructor(id, url = 'cosy://newtab') {
    this.id = id;
    this.url = url;
    this.title = '新标签页';
    this.favicon = null;
    this.view = null;
    this.isLoading = false;
    this.retry403 = false;
    this.bookmarked = false;
    this.canGoBack = false;
    this.canGoForward = false;
  }
}

function getHttpStatusCode(errorCode) {
  const errorMap = {
    '-105': '404', '-106': '400', '-102': '404', '-109': '404',
    '-118': '404', '-324': '500', '-501': '501', '-6': '404', '-3': '403'
  };
  return errorMap[errorCode.toString()] || '500';
}

function getErrorMessage(errorCode) {
  const messageMap = {
    '-105': '无法找到服务器', '-106': '网络连接已断开', '-102': '连接被拒绝',
    '-109': '地址无法访问', '-118': '连接超时', '-324': '服务器返回空响应',
    '-501': '不安全的响应', '-6': '文件未找到', '-3': '访问被拒绝'
  };
  return messageMap[errorCode.toString()] || '发生未知错误';
}

function getBrowserErrorText(errorCode) {
  const errorTextMap = {
    '-105': 'ERR_NAME_NOT_RESOLVED', '-106': 'ERR_INTERNET_DISCONNECTED',
    '-102': 'ERR_CONNECTION_REFUSED', '-109': 'ERR_ADDRESS_UNREACHABLE',
    '-118': 'ERR_CONNECTION_TIMED_OUT', '-324': 'ERR_EMPTY_RESPONSE',
    '-501': 'ERR_INSECURE_RESPONSE', '-6': 'ERR_FILE_NOT_FOUND', '-3': 'ERR_ACCESS_DENIED'
  };
  return errorTextMap[errorCode.toString()] || 'UNKNOWN_ERROR';
}

function isSafeUrl(url) {
  try {
    const parsed = new URL(url);
    return ALLOWED_PROTOCOLS.has(parsed.protocol);
  } catch {
    return false;
  }
}

function sanitizePath(inputPath, baseDir) {
  const resolved = path.resolve(baseDir, inputPath);
  const normalized = path.normalize(resolved);
  if (!isPathInDir(normalized, baseDir)) return null;
  return normalized;
}

function isPathInDir(filePath, dir) {
  return filePath === dir || filePath.startsWith(dir + path.sep);
}

function isValidColor(str) {
  return typeof str === 'string' && /^#[0-9a-fA-F]{3,8}$/.test(str);
}

function getCurrentTabWebContents() {
  const tab = tabs[currentTabIndex];
  return tab?.view?.webContents || null;
}

function zoomIn() {
  const wc = getCurrentTabWebContents();
  if (wc) wc.setZoomLevel(wc.getZoomLevel() + ZOOM_STEP);
}

function zoomOut() {
  const wc = getCurrentTabWebContents();
  if (wc) wc.setZoomLevel(wc.getZoomLevel() - ZOOM_STEP);
}

function resetZoom() {
  const wc = getCurrentTabWebContents();
  if (wc) wc.setZoomLevel(0);
}

function toggleDevTools() {
  const wc = getCurrentTabWebContents();
  if (wc) wc.toggleDevTools();
}

function goHome() {
  const tab = tabs[currentTabIndex];
  if (tab) {
    tab.url = 'cosy://newtab';
    loadTabContent(tab);
    sendToRenderer('tab-updated', { id: tab.id, url: tab.url, title: '新标签页' });
  }
}

async function showOpenFileDialog() {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: '打开文件',
    properties: ['openFile'],
    filters: [
      { name: '网页文件', extensions: ['html', 'htm'] },
      { name: '所有文件', extensions: ['*'] }
    ]
  });
  if (!result.canceled && result.filePaths.length > 0) {
    createNewTab(`file://${result.filePaths[0]}`);
  }
}

function addToHistory(url, title) {
  if (!isSafeUrl(url) || url.startsWith('cosy://')) return;
  const existingIndex = history.findIndex(h => h.url === url);
  if (existingIndex !== -1) history.splice(existingIndex, 1);
  history.unshift({ url, title, timestamp: Date.now() });
  if (history.length > MAX_HISTORY_ENTRIES) history = history.slice(0, MAX_HISTORY_ENTRIES);
  saveHistory();
}

function saveHistory() {
  const historyPath = path.join(app.getPath('userData'), 'history.json');
  try {
    fsSync.writeFileSync(historyPath, JSON.stringify(history, null, 2), 'utf-8');
  } catch (e) {
    console.error('保存历史记录失败:', e);
  }
}

function loadHistory() {
  const historyPath = path.join(app.getPath('userData'), 'history.json');
  try {
    if (fsSync.existsSync(historyPath)) {
      history = JSON.parse(fsSync.readFileSync(historyPath, 'utf-8'));
    }
  } catch (e) {
    console.error('读取历史记录失败:', e);
  }
}

function saveBookmarks() {
  const bookmarksPath = path.join(app.getPath('userData'), 'bookmarks.json');
  try {
    fsSync.writeFileSync(bookmarksPath, JSON.stringify(bookmarks, null, 2), 'utf-8');
  } catch (e) {
    console.error('保存书签失败:', e);
  }
}

function loadBookmarks() {
  const bookmarksPath = path.join(app.getPath('userData'), 'bookmarks.json');
  try {
    if (fsSync.existsSync(bookmarksPath)) {
      bookmarks = JSON.parse(fsSync.readFileSync(bookmarksPath, 'utf-8'));
    }
  } catch (e) {
    console.error('读取书签失败:', e);
  }
}

function saveSession() {
  try {
    const sessionPath = path.join(app.getPath('userData'), 'session.json');
    const sessionTabs = tabs
      .filter(tab => !tab.url.startsWith('cosy://') && isSafeUrl(tab.url))
      .map(tab => ({ url: tab.url, title: tab.title }));
    fsSync.writeFileSync(sessionPath, JSON.stringify(sessionTabs, null, 2), 'utf-8');
  } catch (e) {
    console.error('保存会话失败:', e);
  }
}

function loadSession() {
  try {
    const sessionPath = path.join(app.getPath('userData'), 'session.json');
    if (fsSync.existsSync(sessionPath)) {
      const sessionTabs = JSON.parse(fsSync.readFileSync(sessionPath, 'utf-8'));
      if (Array.isArray(sessionTabs) && sessionTabs.length > 0) {
        return sessionTabs.filter(tab => isSafeUrl(tab.url));
      }
    }
  } catch (e) {
    console.error('读取会话失败:', e);
  }
  return null;
}

function clearSession() {
  try {
    const sessionPath = path.join(app.getPath('userData'), 'session.json');
    if (fsSync.existsSync(sessionPath)) fsSync.unlinkSync(sessionPath);
  } catch (e) {
    console.error('清除会话失败:', e);
  }
}

function addToRecentlyClosed(tab) {
  if (!tab || !tab.url || tab.url.startsWith('cosy://')) return;
  recentlyClosedTabs.push({ url: tab.url, title: tab.title, closedAt: Date.now() });
  if (recentlyClosedTabs.length > MAX_RECENTLY_CLOSED) recentlyClosedTabs.shift();
}

function getLastClosedTab() {
  return recentlyClosedTabs.pop();
}

function isLocalhost(url) {
  try {
    const host = new URL(url).hostname;
    return host === 'localhost' || host === '127.0.0.1' || host === '::1';
  } catch { return false; }
}

function isPrivateNetworkHost(url) {
  try {
    const host = new URL(url).hostname.replace(/^\[|\]$/g, '');
    if (host === 'localhost' || host === '::1' || host.endsWith('.localhost')) return true;
    if (host === '::ffff:127.0.0.1') return true;
    const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (m) {
      const a = +m[1], b = +m[2];
      if (a === 127 || a === 10) return true;
      if (a === 172 && b >= 16 && b <= 31) return true;
      if (a === 192 && b === 168) return true;
      if (a === 169 && b === 254) return true;
      return false;
    }
    return false;
  } catch { return false; }
}

// readStoredSettings 只读不校验，启动时用来还原 darkMode / httpsOnly 等运行时状态。
// 校验交给 save-settings 里的 sanitizeSettings。
function readStoredSettings() {
  try {
    const p = path.join(app.getPath('userData'), 'cosySettings.json');
    if (fsSync.existsSync(p)) return JSON.parse(fsSync.readFileSync(p, 'utf-8'));
  } catch (e) { console.error('读取设置失败:', e); }
  return {};
}

// applyDarkMode 切 Chromium 原生暗色主题，影响滚动条、文件对话框、DevTools 外壳。
// renderer 的 CSS 暗色由 settings-loaded 自己管，这里只管原生 UI。
function applyDarkMode(dark) {
  nativeTheme.themeSource = dark ? 'dark' : 'light';
  sendToRenderer('native-theme-changed', { dark: !!dark });
}

function setupSecurityHeaders() {
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    const headers = details.responseHeaders || {};
    const setIfMissing = (name, value) => {
      if (!headers[name] && !headers[name.toLowerCase()]) headers[name] = value;
    };
    setIfMissing('X-Content-Type-Options', ['nosniff']);
    setIfMissing('X-Frame-Options', ['SAMEORIGIN']);
    setIfMissing('Referrer-Policy', ['strict-origin-when-cross-origin']);
    // 关闭 FLoC / 广告兴趣组 / 隐私令牌等现代浏览器默认放开但我们不需要的特性
    setIfMissing('Permissions-Policy', [
      'interest-cohort=()', 'run-ad-auction=()',
      'private-state-token-issuance=()', 'private-state-token-redemption=()',
      'join-ad-interest-group=()'
    ]);
    const isLocal = details.url.startsWith('cosy://') || details.url.startsWith('file://');
    if (isLocal && !headers['Content-Security-Policy'] && !headers['content-security-policy']) {
      headers['Content-Security-Policy'] = ["default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https:;"];
    }
    callback({ responseHeaders: headers });
  });

  session.defaultSession.webRequest.onBeforeSendHeaders((details, callback) => {
    const headers = details.requestHeaders;
    headers['DNT'] = '1';
    headers['Sec-GPC'] = '1';
    headers['Upgrade-Insecure-Requests'] = '1';
    callback({ requestHeaders: headers });
  });

  session.defaultSession.webRequest.onBeforeRequest((details, callback) => {
    // HTTPS-only 模式：用户可在设置里关掉；私网/回环主机永远保留 http://
    if (httpsOnlyEnabled && details.url.startsWith('http://') && !isPrivateNetworkHost(details.url)) {
      callback({ redirectURL: 'https://' + details.url.slice(7) });
    } else {
      callback({});
    }
  });
}

const ALLOWED_PERMISSIONS = new Set([
  'media', 'geolocation', 'notifications', 'midi', 'midiSysex',
  'pointerLock', 'fullscreen', 'clipboard-read', 'clipboard-sanitized-write',
  'pop-up', 'openExternal'
]);

function setupPermissionHandlers() {
  session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) => {
    callback(ALLOWED_PERMISSIONS.has(permission));
  });
  session.defaultSession.setPermissionCheckHandler((webContents, permission) => {
    return ALLOWED_PERMISSIONS.has(permission);
  });
}

// setupGlobalWebContentsHooks 给所有 webContents 兜底：
// - 任何没被我们显式设置过 windowOpenHandler 的 webContents（扩展后台页、插件 popup、
//   未来新增的窗口等）默认 deny 弹窗，只放行我们白名单里的协议；
// - 拦 will-navigate，不允许跳到 javascript:/data:/vbscript: 这些危险 scheme；
// - beforeunload 弹确认，避免用户关标签时把没保存的表单/SQL 编辑器内容直接丢了。
function setupGlobalWebContentsHooks() {
  app.on('web-contents-created', (_event, contents) => {
    // 主窗口 UI 自己管 navigation，跳过；只给页面 tab 兜底
    if (contents === mainWindow?.webContents) return;

    contents.setWindowOpenHandler(({ url }) => {
      if (!isSafeUrl(url)) return { action: 'deny' };
      // 从 tab 里点 _blank 的，统一丢回我们的 createNewTab
      setImmediate(() => createNewTab(url));
      return { action: 'deny' };
    });

    contents.on('will-navigate', (navEvent, url) => {
      if (!isSafeUrl(url)) {
        navEvent.preventDefault();
      }
    });

    contents.on('will-redirect', (redirectEvent, url) => {
      if (!isSafeUrl(url)) {
        redirectEvent.preventDefault();
      }
    });

    // 页面调 window.close() 之前触发的 beforeunload，弹原生确认
    contents.on('will-prevent-unload', (event) => {
      event.preventDefault();
      const choice = dialog.showMessageBoxSync(mainWindow, {
        type: 'question',
        buttons: ['离开此页', '留在此页'],
        defaultId: 1,
        cancelId: 1,
        title: '确认离开',
        message: '您有尚未保存的更改。确定要离开此页面吗？'
      });
      if (choice === 0) {
        contents.destroy();
      }
    });
  });
}

// setupNetworkStatus 监听 Chromium 的 online/offline 事件，把状态推给 renderer，
// 地址栏/错误页可以据此显示"已断开连接"横幅。
function setupNetworkStatus() {
  const report = () => {
    sendToRenderer('network-status-changed', { online: net.isOnline() });
  };
  app.on('online', report);
  app.on('offline', report);
  // 启动时先报一次当前状态
  setTimeout(report, 500);
}

function getTabLayout() {
  const settingsPath = path.join(app.getPath('userData'), 'cosySettings.json');
  try {
    if (fsSync.existsSync(settingsPath)) {
      const settings = JSON.parse(fsSync.readFileSync(settingsPath, 'utf-8'));
      return settings.tabLayout || 'horizontal';
    }
  } catch (e) {
    console.error('读取设置失败:', e);
  }
  return 'horizontal';
}

function getDefaultTabUrl() {
  const settingsPath = path.join(app.getPath('userData'), 'cosySettings.json');
  try {
    if (fsSync.existsSync(settingsPath)) {
      const settings = JSON.parse(fsSync.readFileSync(settingsPath, 'utf-8'));
      if (settings.defaultTab === 'bing') return 'https://www.bing.com';
      if (settings.defaultTab === 'custom' && settings.customUrl && isSafeUrl(settings.customUrl))
        return settings.customUrl;
    }
  } catch (e) {
    console.error('读取设置失败:', e);
  }
  return 'cosy://newtab';
}

function createWindow() {
  if (mainWindow && !mainWindow.isDestroyed()) return;

  mainWindow = new BrowserWindow({
    width: DEFAULT_WINDOW_WIDTH, height: DEFAULT_WINDOW_HEIGHT,
    minWidth: MIN_WINDOW_WIDTH, minHeight: MIN_WINDOW_HEIGHT,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      enableRemoteModule: false,
      preload: path.join(__dirname, 'preload.js'),
      worldSafeExecuteJavaScript: true,
      spellcheck: true,
    },
    titleBarStyle: 'hidden', frame: false, show: false,
    icon: path.join(__dirname, 'ico.png')
  });

  const tabLayout = getTabLayout();
  const htmlFile = tabLayout === 'vertical' ? 'src/index_vertical.html' : 'src/index.html';
  mainWindow.loadFile(htmlFile);

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    if (fileToOpen) {
      createNewTab(fileToOpen);
      fileToOpen = null;
    } else {
      const savedSession = loadSession();
      if (savedSession && savedSession.length > 0) {
        savedSession.forEach((tab) => createNewTab(tab.url));
        clearSession();
      } else {
        createNewTab(getDefaultTabUrl());
      }
    }
  });

  mainWindow.on('resize', updateBrowserViewBounds);
  mainWindow.on('move', updateBrowserViewBounds);
  mainWindow.once('closed', () => {
    saveSession();
    mainWindow = null;
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (isSafeUrl(url)) createNewTab(url);
    return { action: 'deny' };
  });

  registerShortcuts();
}

function registerShortcuts() {
  if (!mainWindow) return;
  mainWindow.webContents.on('before-input-event', (event, input) => {
    if (input.type !== 'keyDown') return;
    const ctrl = input.control || input.meta;
    const shift = input.shift;
    const alt = input.alt;
    const key = input.key.toLowerCase();

    if (ctrl && key === 't' && !shift) {
      createNewTab();
      event.preventDefault();
    } else if (ctrl && key === 't' && shift) {
      const lastClosedTab = getLastClosedTab();
      if (lastClosedTab) createNewTab(lastClosedTab.url);
      event.preventDefault();
    } else if (ctrl && key === 'w') {
      closeTab(currentTabIndex);
      event.preventDefault();
    } else if (ctrl && key === 'n') {
      createWindow();
      event.preventDefault();
    } else if (ctrl && key === 'k' && shift) {
      const tab = tabs[currentTabIndex];
      if (tab && isSafeUrl(tab.url)) createNewTab(tab.url);
      event.preventDefault();
    } else if (ctrl && key === 'b' && shift) {
      // Ctrl+Shift+B：切换书签栏（Chrome/Edge 惯例）
      sendToRenderer('toggle-bookmarks-bar');
      event.preventDefault();
    } else if (ctrl && key === 'd' && shift) {
      // Ctrl+Shift+D：把所有打开的标签一键加为书签
      const newBookmarks = tabs
        .filter(t => isSafeUrl(t.url) && !t.url.startsWith('cosy://'))
        .map(t => ({ url: t.url, title: t.title, addedDate: new Date().toISOString() }))
        .filter(b => !bookmarks.find(x => x.url === b.url));
      if (newBookmarks.length > 0) {
        bookmarks.push(...newBookmarks);
        saveBookmarks();
        sendToRenderer('bookmarks-updated', bookmarks);
        sendToRenderer('show-toast', `已收藏 ${newBookmarks.length} 个标签页`);
      } else {
        sendToRenderer('show-toast', '没有可收藏的标签页');
      }
      event.preventDefault();
    } else if (ctrl && key === 'tab') {
      const nextIndex = shift
        ? (currentTabIndex - 1 + tabs.length) % tabs.length
        : (currentTabIndex + 1) % tabs.length;
      switchToTab(nextIndex);
      event.preventDefault();
    } else if (ctrl && key === 'l') {
      mainWindow.webContents.send('focus-address-bar');
      event.preventDefault();
    } else if (ctrl && key === 'f') {
      mainWindow.webContents.send('show-find-bar');
      event.preventDefault();
    } else if (ctrl && key === 'j') {
      createNewTab('cosy://downloadlist');
      event.preventDefault();
    } else if (ctrl && key === 'p') {
      const wc = getCurrentTabWebContents();
      if (wc) wc.print({ silent: false, printBackground: true });
      event.preventDefault();
    } else if (ctrl && key === 'u') {
      const tab = tabs[currentTabIndex];
      if (tab && tab.view?.webContents && isSafeUrl(tab.url)) {
        tab.view.webContents.viewSource();
      }
      event.preventDefault();
    } else if (ctrl && key === 'o') {
      showOpenFileDialog();
      event.preventDefault();
    } else if (alt && input.key === 'Home') {
      goHome();
      event.preventDefault();
    } else if (ctrl && key === 'r' && !shift) {
      const wc = getCurrentTabWebContents();
      if (wc) wc.reload();
      event.preventDefault();
    } else if (ctrl && key === 'r' && shift) {
      const wc = getCurrentTabWebContents();
      if (wc) wc.reloadIgnoringCache();
      event.preventDefault();
    } else if (input.key === 'F5' && !shift) {
      const wc = getCurrentTabWebContents();
      if (wc) wc.reload();
      event.preventDefault();
    } else if (input.key === 'F5' && shift) {
      const wc = getCurrentTabWebContents();
      if (wc) wc.reloadIgnoringCache();
      event.preventDefault();
    } else if (input.key === 'F12') {
      toggleDevTools();
      event.preventDefault();
    } else if (input.key === 'Escape') {
      // 现代浏览器惯例：Esc 退出 HTML 全屏
      const wc = getCurrentTabWebContents();
      if (wc && wc.isFullScreen()) {
        wc.exitFullScreen();
        event.preventDefault();
      }
    } else if (ctrl && input.key === '=') {
      zoomIn();
      event.preventDefault();
    } else if (ctrl && input.key === '-') {
      zoomOut();
      event.preventDefault();
    } else if (ctrl && input.key === '0') {
      resetZoom();
      event.preventDefault();
    } else if (alt && input.key === 'ArrowLeft') {
      const wc = getCurrentTabWebContents();
      if (wc?.canGoBack()) wc.goBack();
      event.preventDefault();
    } else if (alt && input.key === 'ArrowRight') {
      const wc = getCurrentTabWebContents();
      if (wc?.canGoForward()) wc.goForward();
      event.preventDefault();
    } else if (ctrl && key === 'd' && !shift) {
      const tab = tabs[currentTabIndex];
      if (tab && isSafeUrl(tab.url) && !tab.url.startsWith('cosy://')) {
        const existing = bookmarks.findIndex(b => b.url === tab.url);
        if (existing === -1) {
          bookmarks.push({ url: tab.url, title: tab.title, addedDate: new Date().toISOString() });
          saveBookmarks();
          tab.bookmarked = true;
          sendToRenderer('bookmarks-updated', bookmarks);
          sendToRenderer('show-toast', '已添加书签');
        } else {
          bookmarks.splice(existing, 1);
          saveBookmarks();
          tab.bookmarked = false;
          sendToRenderer('bookmarks-updated', bookmarks);
          sendToRenderer('show-toast', '已移除书签');
        }
      }
      event.preventDefault();
    } else if (ctrl && key === 'h') {
      mainWindow.webContents.send('show-history');
      event.preventDefault();
    } else if (ctrl && key === 'delete' && shift) {
      sendToRenderer('show-clear-data-dialog');
      event.preventDefault();
    }
  });
}

function getUrlProtocol(url) {
  try { return new URL(url).protocol; } catch { return null; }
}

function createNewTab(url = 'cosy://newtab') {
  if (!isSafeUrl(url)) url = 'cosy://newtab';
  const tabId = Date.now().toString() + Math.random().toString(36).slice(2, 6);
  const tab = new Tab(tabId, url);

  if (getUrlProtocol(url) === 'cosy:') {
    tab.favicon = 'file://' + path.join(__dirname, 'ico.png');
  } else {
    tab.favicon = 'file://' + path.join(__dirname, 'src', 'loading.gif');
  }

  tabs.push(tab);
  currentTabIndex = tabs.length - 1;
  sendToRenderer('tab-created', { id: tab.id, url: tab.url, title: tab.title, favicon: tab.favicon });
  loadTabContent(tab);
  sendToRenderer('tab-switched', { id: tab.id, index: currentTabIndex });
  setTimeout(updateBrowserViewBounds, 0);
  return tab;
}

function showErrorPage(tab, errorCode, errorDescription, validatedURL) {
  const errorParams = new URLSearchParams({
    code: getHttpStatusCode(errorCode),
    message: getErrorMessage(errorCode),
    reason: errorDescription,
    url: validatedURL,
    browserCode: errorCode,
    browserMessage: getBrowserErrorText(errorCode)
  });
  const errorUrl = `file://${__dirname}/src/error.html?${errorParams.toString()}`;
  tab.view.webContents.loadURL(errorUrl);
  tab.url = validatedURL;
  tab.title = `错误 - ${getHttpStatusCode(errorCode)}`;
  sendToRenderer('tab-updated', { id: tab.id, url: validatedURL, title: tab.title });
}

// pushNavState 每次导航完成后同步 canGoBack/canGoForward，让 renderer 知道按钮该灰掉还是点亮
function pushNavState(tab) {
  if (!tab?.view?.webContents) return;
  tab.canGoBack = tab.view.webContents.canGoBack();
  tab.canGoForward = tab.view.webContents.canGoForward();
  sendToRenderer('tab-history-changed', {
    id: tab.id, canGoBack: tab.canGoBack, canGoForward: tab.canGoForward
  });
}

function loadTabContent(tab) {
  if (!tab.view) {
    tab.view = new WebContentsView({
      webPreferences: {
        nodeIntegration: false,
        contextIsolation: true,
        sandbox: true,
        webSecurity: true,
        allowRunningInsecureContent: false,
        enableRemoteModule: false,
        preload: path.join(__dirname, 'preload.js'),
        worldSafeExecuteJavaScript: true,
        spellcheck: true,
      }
    });

    mainWindow.contentView.addChildView(tab.view);
    updateBrowserViewBounds();

    tab.view.webContents.setWindowOpenHandler(({ url, disposition }) => {
      if (!isSafeUrl(url)) return { action: 'deny' };
      if (disposition === 'new-window' || disposition === 'foreground-tab') {
        const newTab = createNewTab(url);
        switchToTab(tabs.indexOf(newTab));
      } else {
        tab.url = url;
        tab.view.webContents.loadURL(url);
      }
      return { action: 'deny' };
    });

    tab.view.webContents.on('will-navigate', (event, navigationUrl) => {
      if (!isSafeUrl(navigationUrl)) { event.preventDefault(); return; }
      tab.url = navigationUrl;
      addToHistory(navigationUrl, tab.title);
      sendToRenderer('tab-updated', { id: tab.id, url: navigationUrl });
    });

    tab.view.webContents.on('did-navigate', () => pushNavState(tab));
    tab.view.webContents.on('did-navigate-in-page', () => pushNavState(tab));

    tab.view.webContents.on('did-redirect-navigation', (event, url) => {
      if (!isSafeUrl(url)) return;
      tab.url = url;
      sendToRenderer('tab-updated', { id: tab.id, url });
    });

    tab.view.webContents.on('page-title-updated', (event, title) => {
      tab.title = title;
      addToHistory(tab.url, title);
      sendToRenderer('tab-updated', { id: tab.id, title });
    });

    tab.view.webContents.on('did-start-loading', () => {
      tab.isLoading = true;
      sendToRenderer('tab-loading', { id: tab.id, loading: true });
    });

    tab.view.webContents.on('did-stop-loading', () => {
      tab.isLoading = false;
      sendToRenderer('tab-loading', { id: tab.id, loading: false });
    });

    tab.view.webContents.on('did-fail-load', (event, errorCode, errorDescription, validatedURL, isMainFrame) => {
      if (isMainFrame) {
        const httpStatus = getHttpStatusCode(errorCode);
        if (httpStatus === '403' && !tab.retry403) {
          tab.retry403 = true;
          tab.view.webContents.loadURL(validatedURL).catch(() => {
            showErrorPage(tab, errorCode, errorDescription, validatedURL);
          });
          return;
        }
        showErrorPage(tab, errorCode, errorDescription, validatedURL);
      }
    });

    tab.view.webContents.on('page-favicon-updated', (event, favicons) => {
      if (favicons.length > 0) {
        let faviconUrl = favicons[0];
        if (faviconUrl.startsWith('/')) {
          try {
            const url = new URL(tab.url);
            faviconUrl = url.origin + faviconUrl;
          } catch { return; }
        }
        if (faviconUrl.startsWith('data:') || faviconUrl.startsWith('http')) {
          tab.favicon = faviconUrl;
          sendToRenderer('tab-updated', { id: tab.id, favicon: tab.favicon });
        }
      }
    });

    tab.view.webContents.on('context-menu', (event, params) => {
      const menu = new Menu();
      if (params.linkURL && isSafeUrl(params.linkURL)) {
        menu.append(new MenuItem({ label: '在新标签页中打开', click: () => createNewTab(params.linkURL) }));
        menu.append(new MenuItem({ label: '复制链接地址', click: () => clipboard.writeText(params.linkURL) }));
        menu.append(new MenuItem({ type: 'separator' }));
      }
      if (params.selectionText) {
        menu.append(new MenuItem({ label: '复制', role: 'copy' }));
        menu.append(new MenuItem({
          label: '搜索所选内容',
          click: () => createNewTab('https://www.bing.com/search?q=' + encodeURIComponent(params.selectionText))
        }));
      }
      if (params.selectionText && params.isEditable) menu.append(new MenuItem({ label: '剪切', role: 'cut' }));
      if (params.isEditable) menu.append(new MenuItem({ label: '粘贴', role: 'paste' }));
      if (menu.items.length > 0) menu.append(new MenuItem({ type: 'separator' }));
      if (isDev) menu.append(new MenuItem({ label: '开发者工具', click: toggleDevTools }));
      menu.popup({ window: mainWindow });
    });

    tab.view.webContents.on('enter-html-full-screen', () => {
      tab.originalBounds = tab.view.bounds;
      const [width, height] = mainWindow.getSize();
      tab.view.setBounds({ x: 0, y: 0, width, height });
      sendToRenderer('html-fullscreen-changed', { isFullscreen: true });
    });

    tab.view.webContents.on('leave-html-full-screen', () => {
      if (tab.originalBounds) {
        tab.view.setBounds(tab.originalBounds);
        tab.originalBounds = null;
      }
      sendToRenderer('html-fullscreen-changed', { isFullscreen: false });
    });
  }

  const protocol = getUrlProtocol(tab.url);
  if (protocol === 'cosy:') {
    try {
      const urlObj = new URL(tab.url);
      const hostname = urlObj.hostname;
      const pageMap = {
        'setting': 'src/settings.html', 'newtab': 'src/newtab.html',
        'extensions': 'src/extensions.html', 'version': 'src/version.html',
        'download': 'src/download', 'downloadlist': 'src/downloadlist.html'
      };
      const filePath = pageMap[hostname];
      if (filePath) tab.view.webContents.loadFile(filePath);
      else showCosyError(tab, '404', '页面未找到', '未注册的cosy协议地址');
    } catch (e) {
      console.error('解析cosy协议URL失败:', e);
      showCosyError(tab, '400', '无效的URL', '无法解析cosy协议地址');
    }
  } else if (isSafeUrl(tab.url)) {
    tab.view.webContents.loadURL(tab.url);
  } else {
    showCosyError(tab, '400', '无效的URL', '不支持的协议');
  }
}

function showCosyError(tab, code, message, reason) {
  const errorParams = new URLSearchParams({ code, message, reason, url: tab.url, browserCode: -3, browserMessage: 'ERR_UNKNOWN_COSY_URL' });
  const errorUrl = `file://${__dirname}/src/error.html?${errorParams.toString()}`;
  tab.view.webContents.loadURL(errorUrl);
  tab.title = `错误 - ${code}`;
  tab.favicon = 'src/error.png';
  sendToRenderer('tab-updated', { id: tab.id, url: tab.url, title: tab.title });
}

function updateBrowserViewBounds() {
  if (tabs.length > 0 && currentTabIndex >= 0) {
    const tab = tabs[currentTabIndex];
    if (tab && tab.view) {
      const [width, height] = mainWindow.getSize();
      const tabLayout = getTabLayout();

      let x, y, w, h;
      if (tabLayout === 'vertical') {
        const tabBarWidth = isTabBarCollapsed ? COLLAPSED_TAB_BAR_WIDTH : DEFAULT_TAB_BAR_WIDTH_VERTICAL;
        x = tabBarWidth; y = 75; w = width - tabBarWidth; h = height - 75;
      } else {
        x = 0; y = DEFAULT_TAB_BAR_HEIGHT_HORIZONTAL; w = width; h = height - DEFAULT_TAB_BAR_HEIGHT_HORIZONTAL;
      }
      tab.view.setBounds({ x, y, width: w, height: h });
    }
  }
}

function switchToTab(tabIndex) {
  if (tabIndex >= 0 && tabIndex < tabs.length) {
    currentTabIndex = tabIndex;
    const tab = tabs[tabIndex];
    if (tab.view) {
      mainWindow.contentView.addChildView(tab.view);
      updateBrowserViewBounds();
    }
    sendToRenderer('tab-switched', { id: tab.id, index: tabIndex });
    pushNavState(tab);
  }
}

function closeTab(tabIndex) {
  if (tabIndex >= 0 && tabIndex < tabs.length) {
    const tab = tabs[tabIndex];
    addToRecentlyClosed(tab);
    if (tab.view) tab.view.webContents.destroy();
    tabs.splice(tabIndex, 1);
    if (tabs.length === 0) {
      createNewTab(getDefaultTabUrl());
      currentTabIndex = 0;
    } else if (currentTabIndex >= tabs.length) {
      currentTabIndex = tabs.length - 1;
    }
    if (tabs.length > 0) switchToTab(currentTabIndex);
    sendToRenderer('tab-closed', tabIndex);
  }
}

// sanitizeDownloadFilename 防 Content-Disposition 路径穿越：
// 服务端可能在 filename 里塞 "../../evil.exe"，直接拼到下载目录会写出目录。
// 这里只取 basename，并剥掉 Windows/Unix 保留字符。
function sanitizeDownloadFilename(name) {
  if (!name || typeof name !== 'string') return 'download';
  let base = path.basename(name.replace(/\\/g, '/'));
  base = base.replace(/[\\/:*?"<>|\x00-\x1f]/g, '_');
  base = base.replace(/^\.+$/, '');
  return base || 'download';
}

// resolveUniqueDownloadPath 如果目标已存在，自动追加 (1)/(2)/... 避免覆盖
function resolveUniqueDownloadPath(dir, filename) {
  const ext = path.extname(filename);
  const stem = path.basename(filename, ext);
  let candidate = path.join(dir, filename);
  let counter = 1;
  while (fsSync.existsSync(candidate)) {
    candidate = path.join(dir, `${stem} (${counter})${ext}`);
    counter++;
  }
  return candidate;
}

function setupDownloadManager() {
  session.defaultSession.on('will-download', (event, item, webContents) => {
    const url = item.getURL();
    if (!isSafeUrl(url)) { event.preventDefault(); return; }

    // 关键修复：不信任服务端给的 filename，先净化
    const safeFilename = sanitizeDownloadFilename(item.getFilename());
    item.setSavePath(path.join(app.getPath('downloads'), safeFilename));

    const totalBytes = item.getTotalBytes();
    let downloadInfo = downloads.find(d => d.url === url && d.item === null && d.isItemValid === false);
    let isNewDownload = false;
    if (downloadInfo) {
      downloadInfo.item = item;
      downloadInfo.filename = safeFilename;
      downloadInfo.totalBytes = totalBytes;
      downloadInfo.isItemValid = true;
      downloadInfo.status = 'downloading';
    } else {
      event.preventDefault();
      downloadInfo = {
        id: Date.now().toString(), url, filename: safeFilename, totalBytes,
        receivedBytes: 0, progress: 0, speed: '0 B/s', status: 'pending',
        startTime: Date.now(), savePath: null, item: null,
        lastUpdate: Date.now(), lastReceivedBytes: 0, isItemValid: false,
        expectedHash: null
      };
      downloads.push(downloadInfo);
      isNewDownload = true;
    }
    currentDownloadInfo = downloadInfo;
    if (isNewDownload) { createNewTab('cosy://download'); return; }
    if (downloadInfo.savePath) {
      item.setSavePath(downloadInfo.savePath);
    } else {
      const defaultSavePath = resolveUniqueDownloadPath(app.getPath('downloads'), safeFilename);
      item.setSavePath(defaultSavePath);
      downloadInfo.savePath = defaultSavePath;
    }
    sendToRenderer('download-status-changed', { id: downloadInfo.id, status: 'downloading' });
    item.on('updated', (event, state) => {
      if (state === 'progressing') {
        const receivedBytes = item.getReceivedBytes();
        const totalBytes = item.getTotalBytes();
        const progress = totalBytes > 0 ? ((receivedBytes / totalBytes) * 100).toFixed(2) : 0;
        const now = Date.now();
        const timeDiff = (now - downloadInfo.lastUpdate) / 1000;
        if (timeDiff > 0) {
          const bytesDiff = receivedBytes - downloadInfo.lastReceivedBytes;
          downloadInfo.speed = formatSpeed(bytesDiff / timeDiff);
        }
        downloadInfo.receivedBytes = receivedBytes;
        downloadInfo.progress = progress;
        downloadInfo.lastUpdate = now;
        downloadInfo.lastReceivedBytes = receivedBytes;
        downloadInfo.status = 'downloading';
        sendToRenderer('download-progress', { id: downloadInfo.id, receivedBytes, totalBytes, progress, speed: downloadInfo.speed });
      }
    });
    item.on('done', (event, state) => {
      downloadInfo.isItemValid = false;
      if (state === 'completed') {
        downloadInfo.status = 'complete';
        downloadInfo.savePath = item.getSavePath();
        sendToRenderer('download-complete', { id: downloadInfo.id, savePath: downloadInfo.savePath });
      } else {
        downloadInfo.status = 'error';
        sendToRenderer('download-error', { id: downloadInfo.id });
      }
    });
  });
}

function formatSpeed(bytesPerSecond) {
  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
  let speed = bytesPerSecond;
  let unitIndex = 0;
  while (speed >= 1024 && unitIndex < units.length - 1) { speed /= 1024; unitIndex++; }
  return speed.toFixed(2) + ' ' + units[unitIndex];
}

function generateUserAgent() {
  const platform = os.platform();
  const arch = os.arch();
  const release = os.release();
  const chromeVersion = process.versions.chrome;
  let osInfo;
  switch (platform) {
    case 'win32':
      if (release.startsWith('10.')) osInfo = 'Windows NT 10.0';
      else if (release.startsWith('6.3')) osInfo = 'Windows NT 6.3';
      else if (release.startsWith('6.2')) osInfo = 'Windows NT 6.2';
      else if (release.startsWith('6.1')) osInfo = 'Windows NT 6.1';
      else if (release.startsWith('6.0')) osInfo = 'Windows NT 6.0';
      else osInfo = 'Windows NT 10.0';
      osInfo += arch === 'x64' ? '; Win64; x64' : '; WOW64';
      break;
    case 'darwin':
      const macVersion = release.split('.').slice(0, 2).join('.');
      osInfo = `Macintosh; Intel Mac OS X ${macVersion.replace('.', '_')}`;
      break;
    case 'linux':
      if (arch === 'x64') osInfo = 'X11; Linux x86_64';
      else if (arch === 'arm64') osInfo = 'X11; Linux aarch64';
      else osInfo = 'X11; Linux i686';
      break;
    default: osInfo = 'X11; Unknown';
  }
  return `Mozilla/5.0 (${osInfo}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeVersion} OpenCosyBrowser/1.0.0`;
}

if (process.argv.length > 1) {
  const arg = process.argv[1];
  if (arg && (arg.endsWith('.html') || arg.endsWith('.htm'))) fileToOpen = `file://${arg}`;
  if (arg && (arg.startsWith('http://') || arg.startsWith('https://') || arg.startsWith('cosy://'))) fileToOpen = arg;
}

app.on('open-file', (event, filePath) => {
  event.preventDefault();
  if (filePath && (filePath.endsWith('.html') || filePath.endsWith('.htm'))) {
    const fileUrl = `file://${filePath}`;
    if (mainWindow && mainWindow.isReady()) {
      const newTab = createNewTab(fileUrl);
      switchToTab(tabs.indexOf(newTab));
    } else {
      fileToOpen = fileUrl;
    }
  }
});

app.whenReady().then(async () => {
  loadHistory();
  loadBookmarks();

  // 启动时还原 darkMode / httpsOnly 等运行时状态
  const stored = readStoredSettings();
  applyDarkMode(!!stored.darkMode);
  httpsOnlyEnabled = stored.httpsOnly !== false;

  if (process.platform === 'win32') app.setAsDefaultProtocolClient('cosy');

  protocol.registerFileProtocol('cosy', (request, callback) => {
    try {
      const urlObj = new URL(request.url);
      const hostname = urlObj.hostname;
      const pageMap = {
        'setting': path.join(__dirname, 'src', 'settings.html'),
        'newtab': path.join(__dirname, 'src', 'newtab.html'),
        'extensions': path.join(__dirname, 'src', 'extensions.html'),
        'version': path.join(__dirname, 'src', 'version.html'),
        'download': path.join(__dirname, 'src', 'download', 'index.html'),
        'downloadlist': path.join(__dirname, 'src', 'downloadlist.html')
      };
      const filePath = pageMap[hostname] || path.join(__dirname, 'src', 'newtab.html');
      callback({ path: filePath });
    } catch (e) {
      console.error('注册cosy协议失败:', e);
      callback({ path: path.join(__dirname, 'src', 'newtab.html') });
    }
  });

  protocol.registerFileProtocol('file', (request, callback) => {
    try {
      const requestedPath = decodeURIComponent(request.url.substr(7));
      const resolvedPath = path.resolve(requestedPath);
      if (getSafeDirs().some(dir => isPathInDir(resolvedPath, dir))) {
        callback({ path: resolvedPath });
      } else {
        callback({ error: -3 });
      }
    } catch (e) {
      console.error('注册file协议失败:', e);
      callback({ error: -3 });
    }
  });

  setupPermissionHandlers();
  setupSecurityHeaders();
  setupDownloadManager();
  setupGlobalWebContentsHooks();
  setupNetworkStatus();
  try { session.defaultSession.setSpellCheckerLanguages(SPELLCHECK_LANGUAGES); }
  catch (e) { console.error('设置拼写检查语言失败:', e); }
  session.defaultSession.setUserAgent(generateUserAgent());
  createWindow();
  await loadEnabledExtensions();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('open-url', (event, url) => {
  event.preventDefault();
  if (!isSafeUrl(url)) return;
  if (!mainWindow || mainWindow.isDestroyed()) createWindow();
  setTimeout(() => {
    if (url.startsWith('cosy://') || url.startsWith('http://') || url.startsWith('https://')) {
      createNewTab(url);
    }
  }, 100);
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

ipcMain.on('window-control', (event, action) => {
  if (!isMainSender(event)) return;
  switch (action) {
    case 'minimize': mainWindow.minimize(); break;
    case 'maximize': mainWindow.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize(); break;
    case 'close': mainWindow.close(); break;
  }
});

ipcMain.on('toggle-tabbar-collapse', (event, collapsed) => {
  if (!isMainSender(event)) return;
  isTabBarCollapsed = collapsed;
  updateBrowserViewBounds();
});

ipcMain.handle('navigate-tab', (event, { tabId, url }) => {
  if (!isMainSender(event)) return { success: false, error: 'Unauthorized' };
  if (!isSafeUrl(url)) return { success: false, error: 'Unsafe URL' };
  const tab = tabs.find(t => t.id === tabId);
  if (tab) {
    tab.url = url;
    loadTabContent(tab);
    sendToRenderer('tab-updated', { id: tab.id, url });
    return { success: true };
  }
  return { success: false };
});

ipcMain.handle('navigate-back', (event) => {
  if (!isMainSender(event)) return { success: false };
  const wc = getCurrentTabWebContents();
  if (wc?.canGoBack()) { wc.goBack(); return { success: true }; }
  return { success: false };
});

ipcMain.handle('navigate-forward', (event) => {
  if (!isMainSender(event)) return { success: false };
  const wc = getCurrentTabWebContents();
  if (wc?.canGoForward()) { wc.goForward(); return { success: true }; }
  return { success: false };
});

ipcMain.handle('reload-tab', (event, hard) => {
  if (!isMainSender(event)) return { success: false };
  const wc = getCurrentTabWebContents();
  if (!wc) return { success: false };
  if (hard) wc.reloadIgnoringCache(); else wc.reload();
  return { success: true };
});

ipcMain.handle('stop-loading', (event) => {
  if (!isMainSender(event)) return { success: false };
  const wc = getCurrentTabWebContents();
  if (wc) wc.stop();
  return { success: true };
});

ipcMain.handle('duplicate-tab', (event, tabIndex) => {
  if (!isMainSender(event)) return { success: false };
  const idx = typeof tabIndex === 'number' && tabIndex >= 0 ? tabIndex : currentTabIndex;
  const tab = tabs[idx];
  if (!tab || !isSafeUrl(tab.url)) return { success: false };
  const newTab = createNewTab(tab.url);
  return { id: newTab.id, index: tabs.indexOf(newTab) };
});

ipcMain.handle('create-tab', (event, url) => {
  if (!isMainSender(event)) return { success: false };
  if (!isSafeUrl(url)) url = 'cosy://newtab';
  const tab = createNewTab(url);
  return { id: tab.id, index: tabs.length - 1 };
});

ipcMain.handle('close-tab', (event, tabIndex) => {
  if (!isMainSender(event)) return { success: false };
  closeTab(tabIndex);
  return { success: true };
});

ipcMain.handle('switch-tab', (event, tabIndex) => {
  if (!isMainSender(event)) return { success: false };
  switchToTab(tabIndex);
  return { success: true };
});

ipcMain.on('navigate-to-url', (event, url) => {
  if (!isMainSender(event)) return;
  if (url && isSafeUrl(url)) createNewTab(url);
});

ipcMain.on('get-download-info', (event) => {
  if (currentDownloadInfo) {
    event.reply('download-info', {
      url: currentDownloadInfo.url,
      filename: currentDownloadInfo.filename,
      totalBytes: currentDownloadInfo.totalBytes || 0
    });
  }
});

ipcMain.on('start-download', (event, data) => {
  if (!isMainSender(event)) return;
  if (currentDownloadInfo) {
    try {
      let savePath;
      if (data.savePath) {
        savePath = path.resolve(data.savePath);
        if (!isInSafeDirs(savePath)) {
          savePath = path.join(app.getPath('downloads'), currentDownloadInfo.filename);
        }
      } else {
        savePath = path.join(app.getPath('downloads'), currentDownloadInfo.filename);
      }
      if (currentDownloadInfo.item && currentDownloadInfo.isItemValid) {
        currentDownloadInfo.item.setSavePath(savePath);
        currentDownloadInfo.savePath = savePath;
        currentDownloadInfo.status = 'downloading';
      } else {
        currentDownloadInfo.savePath = savePath;
        currentDownloadInfo.status = 'pending';
        currentDownloadInfo.item = null;
        currentDownloadInfo.isItemValid = false;
        session.defaultSession.downloadURL(currentDownloadInfo.url);
      }
      sendToRenderer('download-started', { id: currentDownloadInfo.id });
    } catch (e) {
      console.error('启动下载失败:', e);
      currentDownloadInfo.isItemValid = false;
      currentDownloadInfo.status = 'error';
    }
  }
});

ipcMain.on('show-save-dialog', (event, data) => {
  if (!isMainSender(event)) return;
  dialog.showSaveDialog(mainWindow, {
    defaultPath: path.join(app.getPath('downloads'), data.defaultName || 'download'),
    filters: [{ name: 'All Files', extensions: ['*'] }]
  }).then(result => {
    if (!result.canceled && result.filePath) {
      if (currentDownloadInfo && currentDownloadInfo.item && currentDownloadInfo.isItemValid) {
        try {
          const state = currentDownloadInfo.item.getState();
          if (state === 'progressing' || state === 'interrupted') currentDownloadInfo.item.cancel();
          currentDownloadInfo.isItemValid = false;
          currentDownloadInfo.status = 'error';
        } catch (e) { console.error('取消下载以另存为失败:', e); }
      }
      if (currentDownloadInfo) {
        currentDownloadInfo.savePath = result.filePath;
        currentDownloadInfo.status = 'pending';
        currentDownloadInfo.item = null;
        currentDownloadInfo.isItemValid = false;
      }
      if (data.url && isSafeUrl(data.url)) session.defaultSession.downloadURL(data.url);
      event.reply('download-started', { id: currentDownloadInfo ? currentDownloadInfo.id : null });
    }
  });
});

ipcMain.on('get-downloads', (event) => {
  const serializableDownloads = downloads.map(d => ({
    id: d.id, url: d.url, filename: d.filename, totalBytes: d.totalBytes,
    receivedBytes: d.receivedBytes, progress: d.progress, speed: d.speed,
    status: d.status, startTime: d.startTime, savePath: d.savePath
  }));
  event.reply('downloads-list', serializableDownloads);
});

ipcMain.on('pause-download', (event, id) => {
  if (!isMainSender(event)) return;
  const download = downloads.find(d => d.id === id);
  if (download && download.item && download.isItemValid) {
    try {
      if (download.item.getState() === 'progressing') {
        download.item.pause();
        download.status = 'paused';
        sendToRenderer('download-status-changed', { id: download.id, status: 'paused' });
      }
    } catch (e) {
      console.error('暂停下载失败:', e);
      download.isItemValid = false; download.status = 'error';
      sendToRenderer('download-status-changed', { id: download.id, status: 'error' });
    }
  }
});

ipcMain.on('resume-download', (event, id) => {
  if (!isMainSender(event)) return;
  const download = downloads.find(d => d.id === id);
  if (download && download.item && download.isItemValid) {
    try {
      const state = download.item.getState();
      if (state === 'interrupted' || state === 'cancelled') {
        download.item.resume();
        download.status = 'downloading';
        sendToRenderer('download-status-changed', { id: download.id, status: 'downloading' });
      }
    } catch (e) {
      console.error('恢复下载失败:', e);
      download.isItemValid = false; download.status = 'error';
      sendToRenderer('download-status-changed', { id: download.id, status: 'downloading' });
    }
  }
});

ipcMain.on('cancel-download', (event, id) => {
  if (!isMainSender(event)) return;
  const download = downloads.find(d => d.id === id);
  if (download && download.item && download.isItemValid) {
    try {
      const state = download.item.getState();
      if (state === 'progressing' || state === 'interrupted') download.item.cancel();
      download.isItemValid = false; download.status = 'error';
      sendToRenderer('download-status-changed', { id: download.id, status: 'error' });
    } catch (e) {
      console.error('取消下载失败:', e);
      download.isItemValid = false; download.status = 'error';
      sendToRenderer('download-status-changed', { id: download.id, status: 'error' });
    }
  }
});

ipcMain.on('retry-download', (event, data) => {
  if (!isMainSender(event)) return;
  const { url } = data;
  if (url && isSafeUrl(url)) session.defaultSession.downloadURL(url);
});

ipcMain.on('remove-download', (event, id) => {
  if (!isMainSender(event)) return;
  const index = downloads.findIndex(d => d.id === id);
  if (index !== -1) {
    downloads.splice(index, 1);
    sendToRenderer('download-removed', { id });
  }
});

ipcMain.on('open-file', (event, filePath) => {
  if (!isMainSender(event)) return;
  const resolved = path.resolve(filePath);
  if (isInSafeDirs(resolved) && fsSync.existsSync(resolved)) shell.openPath(resolved);
});

ipcMain.on('open-folder', (event, filePath) => {
  if (!isMainSender(event)) return;
  const resolved = path.resolve(filePath);
  if (isInSafeDirs(resolved) && fsSync.existsSync(resolved)) shell.showItemInFolder(resolved);
});

ipcMain.on('clear-downloads', (event) => {
  if (!isMainSender(event)) return;
  downloads = [];
  currentDownloadInfo = null;
  sendToRenderer('downloads-cleared');
  setTimeout(() => {
    sendToRenderer('clear-downloads-success', '下载列表已成功清空');
  }, 100);
});

ipcMain.handle('get-current-tab', (event) => {
  if (!isMainSender(event)) return null;
  if (tabs.length > 0 && currentTabIndex >= 0) {
    const tab = tabs[currentTabIndex];
    return {
      id: tab.id, url: tab.url, title: tab.title, favicon: tab.favicon,
      isLoading: tab.isLoading, canGoBack: tab.canGoBack, canGoForward: tab.canGoForward
    };
  }
  return null;
});

ipcMain.handle('get-all-tabs', (event) => {
  if (!isMainSender(event)) return [];
  return tabs.map(tab => ({
    id: tab.id, url: tab.url, title: tab.title, favicon: tab.favicon,
    isLoading: tab.isLoading, canGoBack: tab.canGoBack, canGoForward: tab.canGoForward
  }));
});

ipcMain.on('close-current-tab', (event) => {
  if (!isMainSender(event)) return;
  if (tabs.length > 0) closeTab(currentTabIndex);
});

ipcMain.on('find-in-page', (event, { text, forward }) => {
  if (!isMainSender(event)) return;
  const wc = getCurrentTabWebContents();
  if (wc && text) wc.findInPage(text, { forward, matchCase: false });
});

ipcMain.on('stop-find', (event) => {
  if (!isMainSender(event)) return;
  const wc = getCurrentTabWebContents();
  if (wc) wc.stopFindInPage('clearSelection');
});

ipcMain.on('show-more-options-menu', (event, position) => {
  if (!isMainSender(event)) return;
  const menu = new Menu();
  const wc = getCurrentTabWebContents();
  const currentZoomLevel = wc ? wc.getZoomLevel() : 0;
  const currentZoomPercent = Math.round(Math.pow(1.2, currentZoomLevel) * 100);
  menu.append(new MenuItem({ label: `重置缩放 (当前: ${currentZoomPercent}%)`, click: resetZoom }));
  menu.append(new MenuItem({ label: '放大', click: zoomIn }));
  menu.append(new MenuItem({ label: '缩小', click: zoomOut }));
  menu.append(new MenuItem({ type: 'separator' }));
  menu.append(new MenuItem({
    label: '重新打开已关闭的标签页 (Ctrl+Shift+T)',
    click: () => {
      const lastClosedTab = getLastClosedTab();
      if (lastClosedTab) createNewTab(lastClosedTab.url);
    }
  }));
  menu.popup({ window: mainWindow, x: position.x, y: position.y });
});

function createContextMenu(menuType, selectedText = '') {
  const menu = new Menu();
  if (menuType === 'selection') {
    if (selectedText) {
      menu.append(new MenuItem({ label: '复制', click: () => { if (mainWindow?.webContents) mainWindow.webContents.copy(); } }));
      menu.append(new MenuItem({ type: 'separator' }));
    }
    menu.append(new MenuItem({ label: '主页', click: goHome }));
    menu.append(new MenuItem({ label: '设置', click: () => createNewTab('cosy://setting') }));
    menu.append(new MenuItem({ type: 'separator' }));
    if (isDev) menu.append(new MenuItem({ label: '开发者工具', click: toggleDevTools }));
  } else {
    if (isDev) menu.append(new MenuItem({ label: '开发者工具', click: toggleDevTools }));
    menu.append(new MenuItem({ label: '返回主页', click: goHome }));
    menu.append(new MenuItem({ label: '设置', click: () => createNewTab('cosy://setting') }));
  }
  return menu;
}

const userDataPath = path.join(os.homedir(), 'AppData', 'Roaming', 'OpenCosy', 'browser', 'userdata');
const extensionsPath = path.join(userDataPath, 'extensions');
const configPath = path.join(extensionsPath, 'config.json');

async function ensureDirectories() {
  try {
    await fs.mkdir(userDataPath, { recursive: true });
    await fs.mkdir(extensionsPath, { recursive: true });
  } catch (e) { console.error('创建目录失败:', e); }
}

async function readExtensionsConfig() {
  try {
    await ensureDirectories();
    if (fsSync.existsSync(configPath)) return JSON.parse(await fs.readFile(configPath, 'utf8'));
  } catch (e) { console.error('读取插件配置失败:', e); }
  return { extensions: [] };
}

async function saveExtensionsConfig(config) {
  try {
    await ensureDirectories();
    await fs.writeFile(configPath, JSON.stringify(config, null, 2));
    return true;
  } catch (e) { console.error('保存插件配置失败:', e); return false; }
}

async function validateExtensionFolder(folderPath) {
  try {
    const manifestPath = path.join(folderPath, 'manifest.json');
    if (!fsSync.existsSync(manifestPath)) return { valid: false, error: '文件夹中未找到manifest.json文件' };
    const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
    if (!manifest.name) return { valid: false, error: 'manifest.json中缺少name字段' };
    if (!manifest.version) return { valid: false, error: 'manifest.json中缺少version字段' };
    if (!manifest.manifest_version) return { valid: false, error: 'manifest.json中缺少manifest_version字段' };
    if (manifest.permissions && Array.isArray(manifest.permissions)) {
      const dangerousPermissions = ['<all_urls>', 'tabs', 'history', 'bookmarks', 'cookies', 'webRequest', 'webRequestBlocking', 'proxy', 'management', 'debugger', 'nativeMessaging'];
      if (manifest.permissions.some(p => dangerousPermissions.includes(p))) {
        return { valid: false, error: '插件请求了危险权限，已被拒绝加载' };
      }
    }
    return { valid: true, manifest };
  } catch (e) { return { valid: false, error: '读取manifest.json失败: ' + e.message }; }
}

function isSafeEntryName(name) {
  return name && name !== '.' && name !== '..' && !name.includes('/') && !name.includes('\\') && !path.isAbsolute(name);
}

// copyExtensionToStorage 递归复制扩展文件到 extensionsPath。
// 安全关键：用 lstat 而不是 stat，并且跳过 symlink。否则一个恶意扩展包里塞个
// 符号链接指到 C:\Users\xxx\.ssh\id_rsa，我们会把私钥复制进扩展目录，
// renderer 里的扩展脚本就能直接读到。
async function copyExtensionToStorage(sourcePath, extensionId) {
  try {
    const targetPath = path.join(extensionsPath, extensionId);
    await fs.mkdir(targetPath, { recursive: true });
    const files = await fs.readdir(sourcePath);
    for (const file of files) {
      if (!isSafeEntryName(file)) continue;
      const sourceFile = path.join(sourcePath, file);
      const targetFile = path.join(targetPath, file);
      const stat = await fs.lstat(sourceFile);
      if (stat.IsSymbolicLink()) continue;
      if (stat.isDirectory()) await copyExtensionToStorage(sourceFile, path.join(extensionId, file));
      else await fs.copyFile(sourceFile, targetFile);
    }
    return true;
  } catch (e) { console.error('复制插件失败:', e); return false; }
}

async function loadEnabledExtensions() {
  try {
    const config = await readExtensionsConfig();
    for (const ext of config.extensions) {
      if (ext.enabled) await loadExtension(ext);
    }
  } catch (e) { console.error('加载插件失败:', e); }
}

async function loadExtension(extension) {
  try {
    const extensionPath = path.join(extensionsPath, extension.id);
    if (fsSync.existsSync(extensionPath)) {
      await session.defaultSession.loadExtension(extensionPath, { allowFileAccess: false });
      console.log('插件加载成功:', extension.name);
    }
  } catch (e) { console.error('加载插件失败:', extension.name, e); }
}

async function unloadExtension(extensionId) {
  try {
    const extensions = session.defaultSession.getAllExtensions();
    for (const ext of extensions) {
      if (ext.id === extensionId) { await session.defaultSession.removeExtension(extensionId); break; }
    }
  } catch (e) { console.error('卸载插件失败:', extensionId, e); }
}

ipcMain.handle('add-extension', async (event, folderPath) => {
  if (!isMainSender(event)) return { success: false, error: 'Unauthorized' };
  try {
    const validation = await validateExtensionFolder(folderPath);
    if (!validation.valid) return { success: false, error: validation.error };
    const { manifest } = validation;
    const sanitizedName = manifest.name.replace(/[^a-zA-Z0-9]/g, '_');
    const sanitizedVersion = String(manifest.version).replace(/[^a-zA-Z0-9._-]/g, '_');
    const extensionId = `${sanitizedName}_${sanitizedVersion}`;
    const config = await readExtensionsConfig();
    if (config.extensions.find(ext => ext.id === extensionId)) return { success: false, error: '该插件已存在' };
    const copySuccess = await copyExtensionToStorage(folderPath, extensionId);
    if (!copySuccess) return { success: false, error: '复制插件文件失败' };
    let iconPath = '';
    if (manifest.icons) {
      const iconSizes = Object.keys(manifest.icons).sort((a, b) => parseInt(b) - parseInt(a));
      if (iconSizes.length > 0) {
        const iconName = manifest.icons[iconSizes[0]];
        if (isSafeEntryName(iconName)) iconPath = path.join(extensionsPath, extensionId, iconName);
      }
    }
    const newExtension = {
      id: extensionId, name: manifest.name, version: manifest.version,
      description: manifest.description || '', icon: iconPath,
      path: path.join(extensionsPath, extensionId), enabled: true, addedDate: new Date().toISOString()
    };
    config.extensions.push(newExtension);
    const saveSuccess = await saveExtensionsConfig(config);
    if (!saveSuccess) return { success: false, error: '保存配置失败' };
    return { success: true, extension: newExtension };
  } catch (e) { return { success: false, error: e.message }; }
});

ipcMain.handle('get-extensions', async (event) => {
  if (!isMainSender(event)) return { success: false, error: 'Unauthorized', extensions: [] };
  try {
    const config = await readExtensionsConfig();
    return { success: true, extensions: config.extensions };
  } catch (e) { return { success: false, error: e.message, extensions: [] }; }
});

ipcMain.handle('toggle-extension', async (event, { id, enabled }) => {
  if (!isMainSender(event)) return { success: false, error: 'Unauthorized' };
  try {
    const config = await readExtensionsConfig();
    const extension = config.extensions.find(ext => ext.id === id);
    if (!extension) return { success: false, error: '插件未找到' };
    extension.enabled = enabled;
    const saveSuccess = await saveExtensionsConfig(config);
    if (!saveSuccess) return { success: false, error: '保存配置失败' };
    return { success: true };
  } catch (e) { return { success: false, error: e.message }; }
});

ipcMain.handle('remove-extension', async (event, id) => {
  if (!isMainSender(event)) return { success: false, error: 'Unauthorized' };
  try {
    const config = await readExtensionsConfig();
    const extensionIndex = config.extensions.findIndex(ext => ext.id === id);
    if (extensionIndex === -1) return { success: false, error: '插件未找到' };
    await unloadExtension(id);
    const extensionPath = path.join(extensionsPath, id);
    if (fsSync.existsSync(extensionPath)) await fs.rm(extensionPath, { recursive: true, force: true });
    config.extensions.splice(extensionIndex, 1);
    const saveSuccess = await saveExtensionsConfig(config);
    if (!saveSuccess) return { success: false, error: '保存配置失败' };
    return { success: true };
  } catch (e) { return { success: false, error: e.message }; }
});

ipcMain.handle('browse-folder', async (event) => {
  if (!isMainSender(event)) return { success: false, error: 'Unauthorized' };
  try {
    const result = await dialog.showOpenDialog(mainWindow, { title: '选择插件文件夹', properties: ['openDirectory'] });
    if (!result.canceled && result.filePaths.length > 0) return { success: true, path: result.filePaths[0] };
    return { success: false, error: '用户取消选择' };
  } catch (e) { return { success: false, error: e.message }; }
});

ipcMain.on('show-context-menu', (event, data) => {
  if (!isMainSender(event)) return;
  const menu = createContextMenu(data.menuType, data.selectedText);
  menu.popup();
});

const ALLOWED_SETTING_KEYS = {
  darkMode: v => typeof v === 'boolean',
  httpsOnly: v => typeof v === 'boolean',
  themeColor: v => isValidColor(v),
  defaultTab: v => ['bing', 'custom', 'newtab'].includes(v),
  customUrl: v => typeof v === 'string' && isSafeUrl(v),
  tabLayout: v => ['horizontal', 'vertical'].includes(v),
  searchEngine: v => ['bing', 'google', 'baidu'].includes(v),
  backgroundType: v => ['default', 'custom'].includes(v),
  customBackgroundUrl: v => typeof v === 'string' && isSafeUrl(v),
};

function sanitizeSettings(raw) {
  if (!raw || typeof raw !== 'object') return {};
  const clean = {};
  for (const [key, validate] of Object.entries(ALLOWED_SETTING_KEYS)) {
    if (key in raw && validate(raw[key])) clean[key] = raw[key];
  }
  return clean;
}

ipcMain.on('save-settings', (event, settings) => {
  if (!isMainSender(event)) return;
  try {
    const clean = sanitizeSettings(settings);
    const settingsPath = path.join(app.getPath('userData'), 'cosySettings.json');
    fsSync.writeFileSync(settingsPath, JSON.stringify(clean, null, 2), 'utf-8');
    // 立即把 darkMode / httpsOnly 应用到运行时
    applyDarkMode(clean.darkMode);
    httpsOnlyEnabled = clean.httpsOnly !== false;
    event.reply('settings-saved', { success: true });
  } catch (e) {
    console.error('保存设置失败:', e);
    event.reply('settings-saved', { success: false, error: e.message });
  }
});

ipcMain.on('update-theme-color', (event, color) => {
  if (!isMainSender(event)) return;
  if (!isValidColor(color)) return;
  sendToRenderer('update-theme-color', color);
  tabs.forEach(tab => {
    if (tab.view?.webContents) tab.view.webContents.send('update-theme-color', color);
  });
});

ipcMain.on('get-settings', (event) => {
  if (!isMainSender(event)) return;
  try {
    const settingsPath = path.join(app.getPath('userData'), 'cosySettings.json');
    if (fsSync.existsSync(settingsPath)) event.reply('settings-loaded', JSON.parse(fsSync.readFileSync(settingsPath, 'utf-8')));
    else event.reply('settings-loaded', {});
  } catch (e) {
    console.error('读取设置失败:', e);
    event.reply('settings-loaded', {});
  }
});

ipcMain.on('export-config', async (event, content) => {
  if (!isMainSender(event)) return;
  try {
    const result = await dialog.showSaveDialog(mainWindow, {
      title: '导出配置', defaultPath: 'cosy_config.inf',
      filters: [{ name: '配置文件', extensions: ['inf'] }, { name: '所有文件', extensions: ['*'] }]
    });
    if (!result.canceled && result.filePath) {
      fsSync.writeFileSync(result.filePath, content, 'utf-8');
      event.reply('export-config-success', '配置文件导出成功！');
    } else {
      event.reply('export-config-canceled', '导出操作已取消');
    }
  } catch (e) {
    console.error('导出配置失败:', e);
    event.reply('export-config-error', '导出配置失败: ' + e.message);
  }
});

ipcMain.handle('get-bookmarks', (event) => {
  if (!isMainSender(event)) return { success: false, bookmarks: [] };
  return { success: true, bookmarks };
});

ipcMain.handle('get-history', (event) => {
  if (!isMainSender(event)) return { success: false, history: [] };
  return { success: true, history: history.slice(0, 100) };
});

ipcMain.handle('clear-history', (event) => {
  if (!isMainSender(event)) return { success: false };
  history = [];
  saveHistory();
  return { success: true };
});

ipcMain.handle('get-https-only', (event) => {
  if (!isMainSender(event)) return { success: false };
  return { success: true, enabled: httpsOnlyEnabled };
});

ipcMain.handle('get-network-status', (event) => {
  if (!isMainSender(event)) return { success: false };
  return { success: true, online: net.isOnline() };
});

ipcMain.handle('clear-browsing-data', async (event, options) => {
  if (!isMainSender(event)) return { success: false, error: 'Unauthorized' };
  try {
    if (!options || typeof options !== 'object') return { success: false, error: 'Invalid options' };
    const promises = [];
    if (options.cache) promises.push(session.defaultSession.clearCache());
    if (options.cookies) promises.push(session.defaultSession.clearStorageData({ storages: ['cookies', 'localstorage', 'indexdb'] }));
    if (options.history) {
      history = [];
      saveHistory();
    }
    if (options.downloads) {
      downloads = [];
      currentDownloadInfo = null;
    }
    await Promise.all(promises);
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
});
