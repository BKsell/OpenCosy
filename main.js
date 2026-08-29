const { app, BrowserWindow, WebContentsView, ipcMain, session, protocol, Menu, MenuItem, dialog, shell } = require('electron');
const path = require('path');
const fs = require('fs').promises;
const fsSync = require('fs');
const os = require('os');
const crypto = require('crypto');

let mainWindow;
let tabs = [];
let currentTabIndex = 0;
let fileToOpen = null;
let downloads = [];
let currentDownloadInfo = null;
let isTabBarCollapsed = false;

const ALLOWED_PROTOCOLS = new Set(['http:', 'https:', 'file:', 'cosy:']);
const isDev = !app.isPackaged;

class Tab {
  constructor(id, url = 'cosy://newtab') {
    this.id = id;
    this.url = url;
    this.title = '新标签页';
    this.favicon = null;
    this.view = null;
    this.isLoading = false;
    this.retry403 = false;
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
  if (!normalized.startsWith(baseDir)) {
    return null;
  }
  return normalized;
}

function createWindow() {
  if (mainWindow && !mainWindow.isDestroyed()) return;

  mainWindow = new BrowserWindow({
    width: 1200, height: 800, minWidth: 800, minHeight: 600,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      enableRemoteModule: false,
      preload: path.join(__dirname, 'preload.js'),
      worldSafeExecuteJavaScript: true,
    },
    titleBarStyle: 'hidden', frame: false, show: false,
    icon: path.join(__dirname, 'ico.png')
  });

  const settingsPath = path.join(app.getPath('userData'), 'cosySettings.json');
  let tabLayout = 'horizontal';
  try {
    if (fsSync.existsSync(settingsPath)) {
      const settings = JSON.parse(fsSync.readFileSync(settingsPath, 'utf-8'));
      tabLayout = settings.tabLayout || 'horizontal';
    }
  } catch (error) {
    console.error('读取设置失败:', error);
  }

  const htmlFile = tabLayout === 'vertical' ? 'src/index_vertical.html' : 'src/index.html';
  mainWindow.loadFile(htmlFile);

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    if (fileToOpen) {
      createNewTab(fileToOpen);
      fileToOpen = null;
    } else {
      let defaultTabUrl = 'cosy://newtab';
      try {
        if (fsSync.existsSync(settingsPath)) {
          const settings = JSON.parse(fsSync.readFileSync(settingsPath, 'utf-8'));
          if (settings.defaultTab === 'bing') defaultTabUrl = 'https://www.bing.com';
          else if (settings.defaultTab === 'custom' && settings.customUrl && isSafeUrl(settings.customUrl))
            defaultTabUrl = settings.customUrl;
        }
      } catch (error) { console.error('读取设置失败:', error); }
      createNewTab(defaultTabUrl);
    }
  });

  mainWindow.on('resize', updateBrowserViewBounds);
  mainWindow.on('move', updateBrowserViewBounds);
  mainWindow.once('closed', () => { mainWindow = null; });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (isSafeUrl(url)) {
      createNewTab(url);
    }
    return { action: 'deny' };
  });
}

function getUrlProtocol(url) {
  try { return new URL(url).protocol; } catch { return null; }
}

function createNewTab(url = 'cosy://newtab') {
  if (!isSafeUrl(url)) url = 'cosy://newtab';
  const tabId = Date.now().toString();
  const tab = new Tab(tabId, url);

  if (getUrlProtocol(url) === 'cosy:') {
    tab.favicon = 'file://' + path.join(__dirname, 'ico.png');
  } else {
    tab.favicon = 'file://' + path.join(__dirname, 'src', 'loading.gif');
  }

  tabs.push(tab);
  currentTabIndex = tabs.length - 1;
  mainWindow.webContents.send('tab-created', { id: tab.id, url: tab.url, title: tab.title, favicon: tab.favicon });
  loadTabContent(tab);
  mainWindow.webContents.send('tab-switched', { id: tab.id, index: currentTabIndex });
  setTimeout(updateBrowserViewBounds, 0);
  return tab;
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
      if (!isSafeUrl(navigationUrl)) {
        event.preventDefault();
        return;
      }
      tab.url = navigationUrl;
      mainWindow.webContents.send('tab-updated', { id: tab.id, url: navigationUrl });
    });

    tab.view.webContents.on('did-redirect-navigation', (event, url) => {
      if (!isSafeUrl(url)) return;
      tab.url = url;
      mainWindow.webContents.send('tab-updated', { id: tab.id, url });
    });

    tab.view.webContents.on('page-title-updated', (event, title) => {
      tab.title = title;
      mainWindow.webContents.send('tab-updated', { id: tab.id, title });
    });

    tab.view.webContents.on('did-start-loading', () => {
      tab.isLoading = true;
      mainWindow.webContents.send('tab-loading', { id: tab.id, loading: true });
    });

    tab.view.webContents.on('did-stop-loading', () => {
      tab.isLoading = false;
      mainWindow.webContents.send('tab-loading', { id: tab.id, loading: false });
    });

    tab.view.webContents.on('did-fail-load', (event, errorCode, errorDescription, validatedURL, isMainFrame) => {
      if (isMainFrame) {
        const httpStatus = getHttpStatusCode(errorCode);
        if (httpStatus === '403' && !tab.retry403) {
          tab.retry403 = true;
          console.log('检测到403错误，尝试重新加载:', validatedURL);
          tab.view.webContents.loadURL(validatedURL).catch(() => {
            showErrorPage(tab, errorCode, errorDescription, validatedURL);
          });
          return;
        }
        showErrorPage(tab, errorCode, errorDescription, validatedURL);
      }
    });

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
      mainWindow.webContents.send('tab-updated', { id: tab.id, url: validatedURL, title: tab.title });
    }

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
          mainWindow.webContents.send('tab-updated', { id: tab.id, favicon: tab.favicon });
        }
      }
    });

    tab.view.webContents.on('context-menu', (event, params) => {
      const menu = new Menu();
      if (params.linkURL && isSafeUrl(params.linkURL)) {
        menu.append(new MenuItem({ label: '在新标签页中打开', click: () => createNewTab(params.linkURL) }));
        menu.append(new MenuItem({ type: 'separator' }));
      }
      if (params.selectionText) menu.append(new MenuItem({ label: '复制', role: 'copy' }));
      if (params.selectionText && params.isEditable) menu.append(new MenuItem({ label: '剪切', role: 'cut' }));
      if (params.isEditable) menu.append(new MenuItem({ label: '粘贴', role: 'paste' }));
      if (menu.items.length > 0) menu.append(new MenuItem({ type: 'separator' }));
      if (isDev) {
        menu.append(new MenuItem({ label: '开发者工具', click: () => tab.view.webContents.toggleDevTools() }));
      }
      menu.popup({ window: mainWindow });
    });

    tab.view.webContents.on('enter-html-full-screen', () => {
      tab.originalBounds = tab.view.bounds;
      const [width, height] = mainWindow.getSize();
      tab.view.setBounds({ x: 0, y: 0, width, height });
      mainWindow.webContents.send('html-fullscreen-changed', { isFullscreen: true });
    });

    tab.view.webContents.on('leave-html-full-screen', () => {
      if (tab.originalBounds) {
        tab.view.setBounds(tab.originalBounds);
        tab.originalBounds = null;
      }
      mainWindow.webContents.send('html-fullscreen-changed', { isFullscreen: false });
    });

    session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) => {
      const allowedPermissions = new Set(['media', 'geolocation', 'notifications', 'midi', 'midiSysex', 'pointerLock', 'fullscreen', 'openExternal']);
      if (allowedPermissions.has(permission)) {
        callback(true);
      } else {
        callback(false);
      }
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
        'download': 'src/download/index.html', 'downloadlist': 'src/downloadlist.html'
      };
      const filePath = pageMap[hostname];
      if (filePath) {
        tab.view.webContents.loadFile(filePath);
      } else {
        showCosyError(tab, '404', '页面未找到', '未注册的cosy协议地址');
      }
    } catch {
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
  mainWindow.webContents.send('tab-updated', { id: tab.id, url: tab.url, title: tab.title });
}

function updateBrowserViewBounds() {
  if (tabs.length > 0 && currentTabIndex >= 0) {
    const tab = tabs[currentTabIndex];
    if (tab && tab.view) {
      const [width, height] = mainWindow.getSize();
      const settingsPath = path.join(app.getPath('userData'), 'cosySettings.json');
      let tabLayout = 'horizontal';
      try {
        if (fsSync.existsSync(settingsPath)) {
          tabLayout = JSON.parse(fsSync.readFileSync(settingsPath, 'utf-8')).tabLayout || 'horizontal';
        }
      } catch {}

      let x, y, w, h;
      if (tabLayout === 'vertical') {
        const tabBarWidth = isTabBarCollapsed ? 50 : 200;
        x = tabBarWidth; y = 75; w = width - tabBarWidth; h = height - 75;
      } else {
        x = 0; y = 116; w = width; h = height - 116;
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
    mainWindow.webContents.send('tab-switched', { id: tab.id, index: tabIndex });
  }
}

function closeTab(tabIndex) {
  if (tabIndex >= 0 && tabIndex < tabs.length) {
    const tab = tabs[tabIndex];
    if (tab.view) tab.view.webContents.destroy();
    tabs.splice(tabIndex, 1);
    if (tabs.length === 0) {
      let defaultTabUrl = 'cosy://newtab';
      try {
        const settingsPath = path.join(app.getPath('userData'), 'cosySettings.json');
        if (fsSync.existsSync(settingsPath)) {
          const settings = JSON.parse(fsSync.readFileSync(settingsPath, 'utf-8'));
          if (settings.defaultTab === 'bing') defaultTabUrl = 'https://www.bing.com';
          else if (settings.defaultTab === 'custom' && settings.customUrl && isSafeUrl(settings.customUrl))
            defaultTabUrl = settings.customUrl;
        }
      } catch {}
      createNewTab(defaultTabUrl);
      currentTabIndex = 0;
    } else if (currentTabIndex >= tabs.length) {
      currentTabIndex = tabs.length - 1;
    }
    if (tabs.length > 0) switchToTab(currentTabIndex);
    mainWindow.webContents.send('tab-closed', tabIndex);
  }
}

function setupDownloadManager() {
  session.defaultSession.on('will-download', (event, item, webContents) => {
    const url = item.getURL();
    if (!isSafeUrl(url)) {
      event.preventDefault();
      return;
    }
    const filename = item.getFilename();
    const totalBytes = item.getTotalBytes();
    let downloadInfo = downloads.find(d => d.url === url && d.item === null && d.isItemValid === false);
    let isNewDownload = false;
    if (downloadInfo) {
      downloadInfo.item = item;
      downloadInfo.filename = filename;
      downloadInfo.totalBytes = totalBytes;
      downloadInfo.isItemValid = true;
      downloadInfo.status = 'downloading';
    } else {
      event.preventDefault();
      downloadInfo = {
        id: Date.now().toString(), url, filename, totalBytes,
        receivedBytes: 0, progress: 0, speed: '0 B/s', status: 'pending',
        startTime: Date.now(), savePath: null, item: null,
        lastUpdate: Date.now(), lastReceivedBytes: 0, isItemValid: false,
        expectedHash: null
      };
      downloads.push(downloadInfo);
      isNewDownload = true;
    }
    currentDownloadInfo = downloadInfo;
    if (isNewDownload) {
      createNewTab('cosy://download');
      return;
    }
    if (downloadInfo.savePath) {
      item.setSavePath(downloadInfo.savePath);
    } else {
      const defaultSavePath = path.join(app.getPath('downloads'), filename);
      item.setSavePath(defaultSavePath);
      downloadInfo.savePath = defaultSavePath;
    }
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('download-status-changed', { id: downloadInfo.id, status: 'downloading' });
    }
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
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('download-progress', { id: downloadInfo.id, receivedBytes, totalBytes, progress, speed: downloadInfo.speed });
        }
      }
    });
    item.on('done', (event, state) => {
      downloadInfo.isItemValid = false;
      if (state === 'completed') {
        downloadInfo.status = 'complete';
        downloadInfo.savePath = item.getSavePath();
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('download-complete', { id: downloadInfo.id, savePath: downloadInfo.savePath });
        }
      } else {
        downloadInfo.status = 'error';
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('download-error', { id: downloadInfo.id });
        }
      }
    });
    if (isNewDownload) createNewTab('cosy://download');
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
  return `Mozilla/5.0 (${osInfo}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.7559.60 OpenCosyBrowser/1.0.0`;
}

if (process.argv.length > 1) {
  const arg = process.argv[1];
  if (arg && (arg.endsWith('.html') || arg.endsWith('.htm'))) {
    fileToOpen = `file://${arg}`;
  }
  if (arg && (arg.startsWith('http://') || arg.startsWith('https://') || arg.startsWith('cosy://'))) {
    fileToOpen = arg;
  }
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
  if (process.platform === 'win32') {
    app.setAsDefaultProtocolClient('cosy');
  }

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
    } catch {
      callback({ path: path.join(__dirname, 'src', 'newtab.html') });
    }
  });

  protocol.registerFileProtocol('file', (request, callback) => {
    try {
      const requestedPath = decodeURIComponent(request.url.substr(7));
      const resolvedPath = path.resolve(requestedPath);
      const allowedDirs = [
        app.getPath('downloads'),
        app.getPath('documents'),
        app.getPath('desktop'),
        app.getPath('pictures'),
        app.getPath('videos'),
        app.getPath('music'),
        __dirname,
      ];
      const isAllowed = allowedDirs.some(dir => resolvedPath.startsWith(dir));
      if (isAllowed) {
        callback({ path: resolvedPath });
      } else {
        callback({ error: -3 });
      }
    } catch {
      callback({ error: -3 });
    }
  });

  setupDownloadManager();
  const userAgent = generateUserAgent();
  session.defaultSession.setUserAgent(userAgent);
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
  if (!event.senderFrame || event.sender !== mainWindow?.webContents) return;
  switch (action) {
    case 'minimize': mainWindow.minimize(); break;
    case 'maximize': mainWindow.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize(); break;
    case 'close': mainWindow.close(); break;
  }
});

ipcMain.on('toggle-tabbar-collapse', (event, collapsed) => {
  if (event.sender !== mainWindow?.webContents) return;
  isTabBarCollapsed = collapsed;
  updateBrowserViewBounds();
});

ipcMain.handle('navigate-tab', (event, { tabId, url }) => {
  if (!isSafeUrl(url)) return { success: false, error: 'Unsafe URL' };
  const tab = tabs.find(t => t.id === tabId);
  if (tab) {
    tab.url = url;
    loadTabContent(tab);
    mainWindow.webContents.send('tab-updated', { id: tab.id, url });
    return { success: true };
  }
  return { success: false };
});

ipcMain.handle('create-tab', (event, url) => {
  if (!isSafeUrl(url)) url = 'cosy://newtab';
  const tab = createNewTab(url);
  return { id: tab.id, index: tabs.length - 1 };
});

ipcMain.handle('close-tab', (event, tabIndex) => {
  closeTab(tabIndex);
  return { success: true };
});

ipcMain.handle('switch-tab', (event, tabIndex) => {
  switchToTab(tabIndex);
  return { success: true };
});

ipcMain.on('navigate-to-url', (event, url) => {
  if (event.sender !== mainWindow?.webContents) return;
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
  if (currentDownloadInfo) {
    try {
      let savePath;
      if (data.savePath) {
        savePath = path.resolve(data.savePath);
        const allowedDirs = [app.getPath('downloads'), app.getPath('documents'), app.getPath('desktop')];
        if (!allowedDirs.some(dir => savePath.startsWith(dir))) {
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
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('download-started', { id: currentDownloadInfo.id });
      }
    } catch (error) {
      console.log('Start download error:', error.message);
      currentDownloadInfo.isItemValid = false;
      currentDownloadInfo.status = 'error';
    }
  }
});

ipcMain.on('show-save-dialog', (event, data) => {
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
        } catch (error) { console.log('Cancel download for save-as error:', error.message); }
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
  const download = downloads.find(d => d.id === id);
  if (download && download.item && download.isItemValid) {
    try {
      if (download.item.getState() === 'progressing') {
        download.item.pause();
        download.status = 'paused';
        if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('download-status-changed', { id: download.id, status: 'paused' });
      }
    } catch (error) {
      download.isItemValid = false; download.status = 'error';
      if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('download-status-changed', { id: download.id, status: 'error' });
    }
  }
});

ipcMain.on('resume-download', (event, id) => {
  const download = downloads.find(d => d.id === id);
  if (download && download.item && download.isItemValid) {
    try {
      const state = download.item.getState();
      if (state === 'interrupted' || state === 'cancelled') {
        download.item.resume();
        download.status = 'downloading';
        if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('download-status-changed', { id: download.id, status: 'downloading' });
      }
    } catch (error) {
      download.isItemValid = false; download.status = 'error';
      if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('download-status-changed', { id: download.id, status: 'error' });
    }
  }
});

ipcMain.on('cancel-download', (event, id) => {
  const download = downloads.find(d => d.id === id);
  if (download && download.item && download.isItemValid) {
    try {
      const state = download.item.getState();
      if (state === 'progressing' || state === 'interrupted') download.item.cancel();
      download.isItemValid = false; download.status = 'error';
      if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('download-status-changed', { id: download.id, status: 'error' });
    } catch (error) {
      download.isItemValid = false; download.status = 'error';
      if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('download-status-changed', { id: download.id, status: 'error' });
    }
  }
});

ipcMain.on('retry-download', (event, data) => {
  const { url } = data;
  if (url && isSafeUrl(url)) session.defaultSession.downloadURL(url);
});

ipcMain.on('remove-download', (event, id) => {
  const index = downloads.findIndex(d => d.id === id);
  if (index !== -1) {
    downloads.splice(index, 1);
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('download-removed', { id });
  }
});

ipcMain.on('open-file', (event, filePath) => {
  if (fsSync.existsSync(filePath)) shell.openPath(filePath);
});

ipcMain.on('open-folder', (event, filePath) => {
  if (fsSync.existsSync(filePath)) shell.showItemInFolder(filePath);
});

ipcMain.on('clear-downloads', (event) => {
  downloads = [];
  currentDownloadInfo = null;
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('downloads-cleared');
    setTimeout(() => {
      if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('clear-downloads-success', '下载列表已成功清空');
    }, 100);
  }
});

ipcMain.handle('get-current-tab', () => {
  if (tabs.length > 0 && currentTabIndex >= 0) {
    const tab = tabs[currentTabIndex];
    return { id: tab.id, url: tab.url, title: tab.title, favicon: tab.favicon, isLoading: tab.isLoading };
  }
  return null;
});

ipcMain.handle('get-all-tabs', () => {
  return tabs.map(tab => ({ id: tab.id, url: tab.url, title: tab.title, favicon: tab.favicon, isLoading: tab.isLoading }));
});

ipcMain.on('close-current-tab', (event) => {
  if (event.sender !== mainWindow?.webContents) return;
  if (tabs.length > 0) closeTab(currentTabIndex);
});

ipcMain.on('create-tab', (event, url) => {
  if (event.sender !== mainWindow?.webContents) return;
  if (isSafeUrl(url)) createNewTab(url);
});

ipcMain.on('show-more-options-menu', (event, position) => {
  if (event.sender !== mainWindow?.webContents) return;
  const menu = new Menu();
  let currentZoomLevel = 1.0;
  if (tabs.length > 0 && currentTabIndex >= 0) {
    const tab = tabs[currentTabIndex];
    if (tab.view && tab.view.webContents) currentZoomLevel = tab.view.webContents.getZoomLevel();
  }
  const currentZoomPercent = Math.round((Math.pow(1.2, currentZoomLevel)) * 100);
  menu.append(new MenuItem({
    label: `重置缩放 (当前: ${currentZoomPercent}%)`,
    click: () => {
      if (tabs.length > 0 && currentTabIndex >= 0) {
        const tab = tabs[currentTabIndex];
        if (tab.view && tab.view.webContents) tab.view.webContents.setZoomLevel(0);
      }
    }
  }));
  menu.append(new MenuItem({
    label: '放大',
    click: () => {
      if (tabs.length > 0 && currentTabIndex >= 0) {
        const tab = tabs[currentTabIndex];
        if (tab.view && tab.view.webContents) tab.view.webContents.setZoomLevel(tab.view.webContents.getZoomLevel() + 0.5);
      }
    }
  }));
  menu.append(new MenuItem({
    label: '缩小',
    click: () => {
      if (tabs.length > 0 && currentTabIndex >= 0) {
        const tab = tabs[currentTabIndex];
        if (tab.view && tab.view.webContents) tab.view.webContents.setZoomLevel(tab.view.webContents.getZoomLevel() - 0.5);
      }
    }
  }));
  menu.append(new MenuItem({ type: 'separator' }));
  menu.popup({ window: mainWindow, x: position.x, y: position.y });
});

function createContextMenu(menuType, selectedText = '') {
  const menu = new Menu();
  if (menuType === 'selection') {
    if (selectedText) {
      menu.append(new MenuItem({ label: '复制', click: () => { if (mainWindow && mainWindow.webContents) mainWindow.webContents.copy(); } }));
      menu.append(new MenuItem({ type: 'separator' }));
    }
    menu.append(new MenuItem({ label: '主页', click: () => { if (tabs.length > 0 && currentTabIndex >= 0) { const tab = tabs[currentTabIndex]; tab.url = 'cosy://newtab'; loadTabContent(tab); } } }));
    menu.append(new MenuItem({ label: '设置', click: () => createNewTab('cosy://setting') }));
    menu.append(new MenuItem({ type: 'separator' }));
    if (isDev) menu.append(new MenuItem({ label: '开发者工具', click: () => { if (tabs.length > 0 && currentTabIndex >= 0) { const tab = tabs[currentTabIndex]; if (tab.view && tab.view.webContents) tab.view.webContents.toggleDevTools(); } } }));
  } else {
    if (isDev) menu.append(new MenuItem({ label: '开发者工具', click: () => { if (tabs.length > 0 && currentTabIndex >= 0) { const tab = tabs[currentTabIndex]; if (tab.view && tab.view.webContents) tab.view.webContents.toggleDevTools(); } } }));
    menu.append(new MenuItem({ label: '返回主页', click: () => { if (tabs.length > 0 && currentTabIndex >= 0) { const tab = tabs[currentTabIndex]; tab.url = 'cosy://newtab'; loadTabContent(tab); } } }));
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
  } catch (error) { console.error('创建目录失败:', error); }
}

async function readExtensionsConfig() {
  try {
    await ensureDirectories();
    if (fsSync.existsSync(configPath)) return JSON.parse(await fs.readFile(configPath, 'utf8'));
  } catch (error) { console.error('读取插件配置失败:', error); }
  return { extensions: [] };
}

async function saveExtensionsConfig(config) {
  try {
    await ensureDirectories();
    await fs.writeFile(configPath, JSON.stringify(config, null, 2));
    return true;
  } catch (error) { console.error('保存插件配置失败:', error); return false; }
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
      const hasDangerous = manifest.permissions.some(p => dangerousPermissions.includes(p));
      if (hasDangerous) return { valid: false, error: '插件请求了危险权限，已被拒绝加载' };
    }
    return { valid: true, manifest };
  } catch (error) { return { valid: false, error: '读取manifest.json失败: ' + error.message }; }
}

async function copyExtensionToStorage(sourcePath, extensionId) {
  try {
    const targetPath = path.join(extensionsPath, extensionId);
    await fs.mkdir(targetPath, { recursive: true });
    const files = await fs.readdir(sourcePath);
    for (const file of files) {
      const sourceFile = path.join(sourcePath, file);
      const targetFile = path.join(targetPath, file);
      const stat = await fs.stat(sourceFile);
      if (stat.isDirectory()) await copyExtensionToStorage(sourceFile, path.join(extensionId, file));
      else await fs.copyFile(sourceFile, targetFile);
    }
    return true;
  } catch (error) { console.error('复制插件失败:', error); return false; }
}

async function loadEnabledExtensions() {
  try {
    const config = await readExtensionsConfig();
    for (const ext of config.extensions) {
      if (ext.enabled) await loadExtension(ext);
    }
  } catch (error) { console.error('加载插件失败:', error); }
}

async function loadExtension(extension) {
  try {
    const extensionPath = path.join(extensionsPath, extension.id);
    if (fsSync.existsSync(extensionPath)) {
      await session.defaultSession.loadExtension(extensionPath, { allowFileAccess: false });
      console.log('插件加载成功:', extension.name);
    }
  } catch (error) { console.error('加载插件失败:', extension.name, error); }
}

async function unloadExtension(extensionId) {
  try {
    const extensions = session.defaultSession.getAllExtensions();
    for (const ext of extensions) {
      if (ext.id === extensionId) { await session.defaultSession.removeExtension(extensionId); break; }
    }
  } catch (error) { console.error('卸载插件失败:', extensionId, error); }
}

ipcMain.handle('add-extension', async (event, folderPath) => {
  try {
    const validation = await validateExtensionFolder(folderPath);
    if (!validation.valid) return { success: false, error: validation.error };
    const { manifest } = validation;
    const extensionId = `${manifest.name.replace(/[^a-zA-Z0-9]/g, '_')}_${manifest.version}`;
    const config = await readExtensionsConfig();
    if (config.extensions.find(ext => ext.id === extensionId)) return { success: false, error: '该插件已存在' };
    const copySuccess = await copyExtensionToStorage(folderPath, extensionId);
    if (!copySuccess) return { success: false, error: '复制插件文件失败' };
    let iconPath = '';
    if (manifest.icons) {
      const iconSizes = Object.keys(manifest.icons).sort((a, b) => parseInt(b) - parseInt(a));
      if (iconSizes.length > 0) iconPath = path.join(extensionsPath, extensionId, manifest.icons[iconSizes[0]]);
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
  } catch (error) { return { success: false, error: error.message }; }
});

ipcMain.handle('get-extensions', async () => {
  try {
    const config = await readExtensionsConfig();
    return { success: true, extensions: config.extensions };
  } catch (error) { return { success: false, error: error.message, extensions: [] }; }
});

ipcMain.handle('toggle-extension', async (event, { id, enabled }) => {
  try {
    const config = await readExtensionsConfig();
    const extension = config.extensions.find(ext => ext.id === id);
    if (!extension) return { success: false, error: '插件未找到' };
    extension.enabled = enabled;
    const saveSuccess = await saveExtensionsConfig(config);
    if (!saveSuccess) return { success: false, error: '保存配置失败' };
    return { success: true };
  } catch (error) { return { success: false, error: error.message }; }
});

ipcMain.handle('remove-extension', async (event, id) => {
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
  } catch (error) { return { success: false, error: error.message }; }
});

ipcMain.handle('browse-folder', async () => {
  try {
    const result = await dialog.showOpenDialog(mainWindow, { title: '选择插件文件夹', properties: ['openDirectory'] });
    if (!result.canceled && result.filePaths.length > 0) return { success: true, path: result.filePaths[0] };
    return { success: false, error: '用户取消选择' };
  } catch (error) { return { success: false, error: error.message }; }
});

ipcMain.on('show-context-menu', (event, menuType, selectedText) => {
  if (event.sender !== mainWindow?.webContents) return;
  const menu = createContextMenu(menuType, selectedText);
  menu.popup();
});

ipcMain.on('save-settings', (event, settings) => {
  if (event.sender !== mainWindow?.webContents) return;
  try {
    const settingsPath = path.join(app.getPath('userData'), 'cosySettings.json');
    fsSync.writeFileSync(settingsPath, JSON.stringify(settings, null, 2), 'utf-8');
    event.reply('settings-saved', { success: true });
  } catch (error) {
    console.error('保存设置失败:', error);
    event.reply('settings-saved', { success: false, error: error.message });
  }
});

ipcMain.on('update-theme-color', (event, color) => {
  if (event.sender !== mainWindow?.webContents) return;
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('update-theme-color', color);
  tabs.forEach(tab => {
    if (tab.view && tab.view.webContents) tab.view.webContents.send('update-theme-color', color);
  });
});

ipcMain.on('get-settings', (event) => {
  if (event.sender !== mainWindow?.webContents) return;
  try {
    const settingsPath = path.join(app.getPath('userData'), 'cosySettings.json');
    if (fsSync.existsSync(settingsPath)) event.reply('settings-loaded', JSON.parse(fsSync.readFileSync(settingsPath, 'utf-8')));
    else event.reply('settings-loaded', {});
  } catch (error) {
    console.error('读取设置失败:', error);
    event.reply('settings-loaded', {});
  }
});

ipcMain.on('export-config', async (event, content) => {
  if (event.sender !== mainWindow?.webContents) return;
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
  } catch (error) {
    console.error('导出配置失败:', error);
    event.reply('export-config-error', '导出配置失败: ' + error.message);
  }
});
