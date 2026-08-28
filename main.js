const { app, BrowserWindow, WebContentsView, ipcMain, session, protocol, Menu, MenuItem, dialog, shell } = require('electron');
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

function createWindow() {
  if (mainWindow && !mainWindow.isDestroyed()) return;

  mainWindow = new BrowserWindow({
    width: 1200, height: 800, minWidth: 800, minHeight: 600,
    webPreferences: {
      nodeIntegration: true, contextIsolation: false, webSecurity: true,
      allowRunningInsecureContent: false, enableRemoteModule: true
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
  } catch (error) { console.error('读取设置失败:', error); }

  const htmlFile = tabLayout === 'vertical' ? 'src/index_vertical.html' : 'src/index.html';
  mainWindow.loadFile(htmlFile);

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    if (fileToOpen) { createNewTab(fileToOpen); fileToOpen = null; }
    else {
      const sp = path.join(app.getPath('userData'), 'cosySettings.json');
      let defaultTabUrl = 'cosy://newtab';
      try {
        if (fsSync.existsSync(sp)) {
          const s = JSON.parse(fsSync.readFileSync(sp, 'utf-8'));
          if (s.defaultTab === 'bing') defaultTabUrl = 'https://www.bing.com';
          else if (s.defaultTab === 'custom' && s.customUrl) defaultTabUrl = s.customUrl;
        }
      } catch (e) { console.error('读取设置失败:', e); }
      createNewTab(defaultTabUrl);
    }
  });

  mainWindow.on('resize', updateBrowserViewBounds);
  mainWindow.on('move', updateBrowserViewBounds);
  mainWindow.once('closed', () => { mainWindow = null; });
}

function getUrlProtocol(url) {
  try { return new URL(url).protocol; } catch { return null; }
}

function createNewTab(url = 'cosy://newtab') {
  const tabId = Date.now().toString();
  const tab = new Tab(tabId, url);
  tab.favicon = getUrlProtocol(url) === 'cosy:'
    ? 'file://' + path.join(__dirname, 'ico.png')
    : 'file://' + path.join(__dirname, 'src', 'loading.gif');
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
    const isCosy = getUrlProtocol(tab.url) === 'cosy:';
    tab.view = new WebContentsView({
      webPreferences: {
        nodeIntegration: isCosy, contextIsolation: !isCosy, webSecurity: true,
        allowRunningInsecureContent: false, sandbox: !isCosy, enableRemoteModule: false,
        worldSafeExecuteJavaScript: true
      }
    });
    mainWindow.contentView.addChildView(tab.view);
    updateBrowserViewBounds();

    tab.view.webContents.setWindowOpenHandler(({ url, disposition }) => {
      if (disposition === 'new-window' || disposition === 'foreground-tab') {
        const nt = createNewTab(url); switchToTab(tabs.indexOf(nt));
      } else { tab.url = url; tab.view.webContents.loadURL(url); }
      return { action: 'deny' };
    });

    tab.view.webContents.on('will-navigate', (e, navUrl) => {
      tab.url = navUrl; mainWindow.webContents.send('tab-updated', { id: tab.id, url: navUrl });
    });
    tab.view.webContents.on('did-redirect-navigation', (e, url) => {
      tab.url = url; mainWindow.webContents.send('tab-updated', { id: tab.id, url });
    });
    tab.view.webContents.on('new-window', (e, navUrl, fn, disp) => {
      e.preventDefault();
      if (disp === 'new-window' || disp === 'foreground-tab') {
        const nt = createNewTab(navUrl); switchToTab(tabs.indexOf(nt));
      } else { tab.url = navUrl; tab.view.webContents.loadURL(navUrl); }
    });
    tab.view.webContents.on('page-title-updated', (e, title) => {
      tab.title = title; mainWindow.webContents.send('tab-updated', { id: tab.id, title });
    });
    tab.view.webContents.on('did-start-loading', () => {
      tab.isLoading = true; mainWindow.webContents.send('tab-loading', { id: tab.id, loading: true });
    });
    tab.view.webContents.on('did-stop-loading', () => {
      tab.isLoading = false; mainWindow.webContents.send('tab-loading', { id: tab.id, loading: false });
    });
    tab.view.webContents.on('did-fail-load', (e, code, desc, url, isMain) => {
      if (isMain) {
        const status = getHttpStatusCode(code);
        if (status === '403' && !tab.retry403) {
          tab.retry403 = true;
          console.log('403重试:', url);
          tab.view.webContents.loadURL(url).catch(() => showErr(tab, code, desc, url));
          return;
        }
        showErr(tab, code, desc, url);
      }
    });
    function showErr(tab, code, desc, url) {
      const p = new URLSearchParams({ code: getHttpStatusCode(code), message: getErrorMessage(code), reason: desc, url, browserCode: code, browserMessage: getBrowserErrorText(code) });
      tab.view.webContents.loadURL(`file://${__dirname}/src/error.html?${p.toString()}`);
      tab.url = url; tab.title = `错误 - ${getHttpStatusCode(code)}`;
      mainWindow.webContents.send('tab-updated', { id: tab.id, url, title: tab.title });
    }
    tab.view.webContents.on('page-favicon-updated', (e, favicons) => {
      if (favicons.length > 0) {
        let fu = favicons[0];
        if (fu.startsWith('/')) { const u = new URL(tab.url); fu = u.origin + fu; }
        if (fu.startsWith('data:') || fu.startsWith('http')) {
          tab.favicon = fu; mainWindow.webContents.send('tab-updated', { id: tab.id, favicon: fu });
        }
      }
    });
    tab.view.webContents.on('context-menu', (e, params) => {
      const menu = new Menu();
      if (params.linkURL) { menu.append(new MenuItem({ label: '在新标签页中打开', click: () => createNewTab(params.linkURL) })); menu.append(new MenuItem({ type: 'separator' })); }
      if (params.selectionText) menu.append(new MenuItem({ label: '复制', role: 'copy' }));
      if (params.selectionText && params.isEditable) menu.append(new MenuItem({ label: '剪切', role: 'cut' }));
      if (params.isEditable) menu.append(new MenuItem({ label: '粘贴', role: 'paste' }));
      if (menu.items.length > 0) menu.append(new MenuItem({ type: 'separator' }));
      menu.append(new MenuItem({ label: '开发者工具', click: () => tab.view.webContents.toggleDevTools() }));
      menu.popup({ window: mainWindow });
    });
    tab.view.webContents.on('enter-html-full-screen', () => {
      tab.originalBounds = tab.view.bounds;
      const [w, h] = mainWindow.getSize();
      tab.view.setBounds({ x: 0, y: 0, width: w, height: h });
      mainWindow.webContents.send('html-fullscreen-changed', { isFullscreen: true });
    });
    tab.view.webContents.on('leave-html-full-screen', () => {
      if (tab.originalBounds) { tab.view.setBounds(tab.originalBounds); tab.originalBounds = null; }
      mainWindow.webContents.send('html-fullscreen-changed', { isFullscreen: false });
    });
  }

  const proto = getUrlProtocol(tab.url);
  if (proto === 'cosy:') {
    try {
      const host = new URL(tab.url).hostname;
      const pages = { 'setting': 'src/settings.html', 'newtab': 'src/newtab.html', 'extensions': 'src/extensions.html', 'version': 'src/version.html', 'download': 'src/download/index.html', 'downloadlist': 'src/downloadlist.html' };
      const fp = pages[host];
      if (fp) tab.view.webContents.loadFile(fp);
      else {
        const p = new URLSearchParams({ code: '404', message: '页面未找到', reason: '未注册的cosy协议地址', url: tab.url, browserCode: -3, browserMessage: 'ERR_UNKNOWN_COSY_URL' });
        tab.view.webContents.loadURL(`file://${__dirname}/src/error.html?${p.toString()}`);
        tab.title = '错误 - 404'; tab.favicon = 'src/error.png';
        mainWindow.webContents.send('tab-updated', { id: tab.id, url: tab.url, title: tab.title });
      }
    } catch {
      const p = new URLSearchParams({ code: '400', message: '无效的URL', reason: '无法解析cosy协议地址', url: tab.url, browserCode: -3, browserMessage: 'ERR_UNKNOWN_COSY_URL' });
      tab.view.webContents.loadURL(`file://${__dirname}/src/error.html?${p.toString()}`);
      tab.title = '错误 - 400'; tab.favicon = 'src/error.png';
      mainWindow.webContents.send('tab-updated', { id: tab.id, url: tab.url, title: tab.title });
    }
  } else tab.view.webContents.loadURL(tab.url);
}

function updateBrowserViewBounds() {
  if (tabs.length > 0 && currentTabIndex >= 0) {
    const tab = tabs[currentTabIndex];
    if (tab && tab.view) {
      const [w, h] = mainWindow.getSize();
      const sp = path.join(app.getPath('userData'), 'cosySettings.json');
      let layout = 'horizontal';
      try { if (fsSync.existsSync(sp)) layout = JSON.parse(fsSync.readFileSync(sp, 'utf-8')).tabLayout || 'horizontal'; } catch (e) { console.error(e); }
      let x, y, bw, bh;
      if (layout === 'vertical') { const tw = isTabBarCollapsed ? 50 : 200; x = tw; y = 75; bw = w - tw; bh = h - 75; }
      else { x = 0; y = 116; bw = w; bh = h - 116; }
      tab.view.setBounds({ x, y, width: bw, height: bh });
    }
  }
}

function switchToTab(i) {
  if (i >= 0 && i < tabs.length) {
    currentTabIndex = i; const t = tabs[i];
    if (t.view) { mainWindow.contentView.addChildView(t.view); updateBrowserViewBounds(); }
    mainWindow.webContents.send('tab-switched', { id: t.id, index: i });
  }
}

function closeTab(i) {
  if (i >= 0 && i < tabs.length) {
    const t = tabs[i];
    if (t.view) t.view.webContents.destroy();
    tabs.splice(i, 1);
    if (tabs.length === 0) {
      const sp = path.join(app.getPath('userData'), 'cosySettings.json');
      let du = 'cosy://newtab';
      try { if (fsSync.existsSync(sp)) { const s = JSON.parse(fsSync.readFileSync(sp, 'utf-8')); if (s.defaultTab === 'bing') du = 'https://www.bing.com'; else if (s.defaultTab === 'custom' && s.customUrl) du = s.customUrl; } } catch (e) { console.error(e); }
      createNewTab(du); currentTabIndex = 0;
    } else if (currentTabIndex >= tabs.length) currentTabIndex = tabs.length - 1;
    if (tabs.length > 0) switchToTab(currentTabIndex);
    mainWindow.webContents.send('tab-closed', i);
  }
}

function setupDownloadManager() {
  session.defaultSession.on('will-download', (event, item) => {
    const url = item.getURL(), filename = item.getFilename(), total = item.getTotalBytes();
    let di = downloads.find(d => d.url === url && d.item === null && d.isItemValid === false);
    let isNew = false;
    if (di) { di.item = item; di.filename = filename; di.totalBytes = total; di.isItemValid = true; di.status = 'downloading'; }
    else {
      event.preventDefault();
      di = { id: Date.now().toString(), url, filename, totalBytes: total, receivedBytes: 0, progress: 0, speed: '0 B/s', status: 'pending', startTime: Date.now(), savePath: null, item: null, lastUpdate: Date.now(), lastReceivedBytes: 0, isItemValid: false };
      downloads.push(di); isNew = true;
    }
    currentDownloadInfo = di;
    if (isNew) { createNewTab('cosy://download'); return; }
    if (di.savePath) item.setSavePath(di.savePath);
    else { const dp = path.join(app.getPath('downloads'), filename); item.setSavePath(dp); di.savePath = dp; }
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('download-status-changed', { id: di.id, status: 'downloading' });
    item.on('updated', (e, state) => {
      if (state === 'progressing') {
        const rb = item.getReceivedBytes(), tb = item.getTotalBytes();
        di.progress = tb > 0 ? ((rb / tb) * 100).toFixed(2) : 0;
        const now = Date.now(), td = (now - di.lastUpdate) / 1000;
        if (td > 0) di.speed = formatSpeed((rb - di.lastReceivedBytes) / td);
        di.receivedBytes = rb; di.lastUpdate = now; di.lastReceivedBytes = rb; di.status = 'downloading';
        if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('download-progress', { id: di.id, receivedBytes: rb, totalBytes: tb, progress: di.progress, speed: di.speed });
      }
    });
    item.on('done', (e, state) => {
      di.isItemValid = false;
      if (state === 'completed') { di.status = 'complete'; di.savePath = item.getSavePath(); if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('download-complete', { id: di.id, savePath: di.savePath }); }
      else { di.status = 'error'; if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('download-error', { id: di.id }); }
    });
    if (isNew) createNewTab('cosy://download');
  });
}

function formatSpeed(bps) {
  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s']; let s = bps, i = 0;
  while (s >= 1024 && i < 3) { s /= 1024; i++; }
  return s.toFixed(2) + ' ' + units[i];
}

function generateUserAgent() {
  const p = os.platform(), a = os.arch(), r = os.release();
  let oi;
  if (p === 'win32') { oi = r.startsWith('10.') ? 'Windows NT 10.0' : r.startsWith('6.3') ? 'Windows NT 6.3' : r.startsWith('6.2') ? 'Windows NT 6.2' : r.startsWith('6.1') ? 'Windows NT 6.1' : 'Windows NT 10.0'; oi += a === 'x64' ? '; Win64; x64' : '; WOW64'; }
  else if (p === 'darwin') { const mv = r.split('.').slice(0, 2).join('.'); oi = `Macintosh; Intel Mac OS X ${mv.replace('.', '_')}`; }
  else if (p === 'linux') oi = a === 'x64' ? 'X11; Linux x86_64' : a === 'arm64' ? 'X11; Linux aarch64' : 'X11; Linux i686';
  else oi = 'X11; Unknown';
  return `Mozilla/5.0 (${oi}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.7559.60 OpenCosyBrowser/1.0.0`;
}

if (process.argv.length > 1) {
  const arg = process.argv[1];
  if (arg && (arg.endsWith('.html') || arg.endsWith('.htm'))) fileToOpen = `file://${arg}`;
  if (arg && (arg.startsWith('http://') || arg.startsWith('https://') || arg.startsWith('cosy://'))) fileToOpen = arg;
}

app.on('open-file', (e, fp) => {
  e.preventDefault();
  if (fp && (fp.endsWith('.html') || fp.endsWith('.htm'))) {
    const fu = `file://${fp}`;
    if (mainWindow && mainWindow.isReady()) { const nt = createNewTab(fu); switchToTab(tabs.indexOf(nt)); }
    else fileToOpen = fu;
  }
});

app.whenReady().then(async () => {
  // v2 安全加固：移除 http/https 默认协议注册，避免静默接管系统默认浏览器
  if (process.platform === 'win32') app.setAsDefaultProtocolClient('cosy');

  protocol.registerFileProtocol('cosy', (req, cb) => {
    const u = req.url.replace('cosy://', '');
    const map = { 'setting': 'src/settings.html', 'newtab': 'src/newtab.html', 'extensions': 'src/extensions.html', 'version': 'src/version.html', 'download': 'src/download/index.html', 'downloadlist': 'src/downloadlist.html' };
    cb({ path: path.join(__dirname, map[u] || 'src/newtab.html') });
  });

  // v2 安全加固：file 协议路径白名单，防止任意本地文件读取
  protocol.registerFileProtocol('file', (req, cb) => {
    try {
      const rp = decodeURIComponent(req.url.substr(7));
      const allowed = [path.resolve(__dirname), path.resolve(app.getPath('downloads')), path.resolve(app.getPath('userData'))];
      const resolved = path.resolve(rp);
      if (allowed.some(d => resolved.startsWith(d + path.sep) || resolved === d)) cb({ path: resolved });
      else { console.log('file协议拒绝:', resolved); cb({ error: -2 }); }
    } catch (e) { console.log('file协议解析失败:', e.message); cb({ error: -2 }); }
  });

  setupDownloadManager();
  session.defaultSession.setUserAgent(generateUserAgent());
  createWindow();
  await loadEnabledExtensions();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

app.on('open-url', (e, url) => {
  e.preventDefault();
  if (!mainWindow || mainWindow.isDestroyed()) createWindow();
  setTimeout(() => { if (url.startsWith('cosy://') || url.startsWith('http://') || url.startsWith('https://')) createNewTab(url); }, 100);
});

app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });

ipcMain.on('window-control', (e, action) => {
  if (action === 'minimize') mainWindow.minimize();
  else if (action === 'maximize') mainWindow.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize();
  else if (action === 'close') mainWindow.close();
});

ipcMain.on('toggle-tabbar-collapse', (e, c) => { isTabBarCollapsed = c; updateBrowserViewBounds(); });

ipcMain.handle('navigate-tab', (e, { tabId, url }) => {
  const t = tabs.find(x => x.id === tabId);
  if (t) { t.url = url; loadTabContent(t); mainWindow.webContents.send('tab-updated', { id: t.id, url }); return { success: true }; }
  return { success: false };
});

ipcMain.handle('create-tab', (e, url) => { const t = createNewTab(url); return { id: t.id, index: tabs.length - 1 }; });
ipcMain.handle('close-tab', (e, i) => { closeTab(i); return { success: true }; });
ipcMain.handle('switch-tab', (e, i) => { switchToTab(i); return { success: true }; });
ipcMain.on('navigate-to-url', (e, url) => { if (url) createNewTab(url); });

ipcMain.on('get-download-info', (e) => {
  if (currentDownloadInfo) e.reply('download-info', { url: currentDownloadInfo.url, filename: currentDownloadInfo.filename, totalBytes: currentDownloadInfo.totalBytes || 0 });
});

ipcMain.on('start-download', (e, data) => {
  if (currentDownloadInfo) {
    try {
      let sp;
      if (data.savePath) {
        // v2 安全加固：下载路径必须在下载目录内
        const dd = path.resolve(app.getPath('downloads'));
        const rs = path.resolve(data.savePath);
        if (!rs.startsWith(dd + path.sep) && rs !== dd) { console.log('下载路径拒绝:', data.savePath); return; }
        sp = rs;
      } else sp = path.join(app.getPath('downloads'), currentDownloadInfo.filename);
      if (currentDownloadInfo.item && currentDownloadInfo.isItemValid) { currentDownloadInfo.item.setSavePath(sp); currentDownloadInfo.savePath = sp; currentDownloadInfo.status = 'downloading'; }
      else { currentDownloadInfo.savePath = sp; currentDownloadInfo.status = 'pending'; currentDownloadInfo.item = null; currentDownloadInfo.isItemValid = false; session.defaultSession.downloadURL(currentDownloadInfo.url); }
      if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('download-started', { id: currentDownloadInfo.id });
    } catch (err) { console.log('下载错误:', err.message); currentDownloadInfo.isItemValid = false; currentDownloadInfo.status = 'error'; }
  }
});

ipcMain.on('show-save-dialog', (e, data) => {
  dialog.showSaveDialog(mainWindow, { defaultPath: path.join(app.getPath('downloads'), data.defaultName || 'download'), filters: [{ name: 'All Files', extensions: ['*'] }] }).then(r => {
    if (!r.canceled && r.filePath) {
      if (currentDownloadInfo && currentDownloadInfo.item && currentDownloadInfo.isItemValid) {
        try { const s = currentDownloadInfo.item.getState(); if (s === 'progressing' || s === 'interrupted') currentDownloadInfo.item.cancel(); currentDownloadInfo.isItemValid = false; currentDownloadInfo.status = 'error'; } catch (err) { console.log(err); }
      }
      if (currentDownloadInfo) { currentDownloadInfo.savePath = r.filePath; currentDownloadInfo.status = 'pending'; currentDownloadInfo.item = null; currentDownloadInfo.isItemValid = false; }
      if (data.url) session.defaultSession.downloadURL(data.url);
      e.reply('download-started', { id: currentDownloadInfo ? currentDownloadInfo.id : null });
    }
  });
});

ipcMain.on('get-downloads', (e) => {
  e.reply('downloads-list', downloads.map(d => ({ id: d.id, url: d.url, filename: d.filename, totalBytes: d.totalBytes, receivedBytes: d.receivedBytes, progress: d.progress, speed: d.speed, status: d.status, startTime: d.startTime, savePath: d.savePath })));
});

function dlAction(id, action) {
  const d = downloads.find(x => x.id === id);
  if (d && d.item && d.isItemValid) {
    try {
      const s = d.item.getState();
      if (action === 'pause' && s === 'progressing') d.item.pause();
      else if (action === 'resume' && (s === 'interrupted' || s === 'cancelled')) d.item.resume();
      else if (action === 'cancel' && (s === 'progressing' || s === 'interrupted')) d.item.cancel();
      d.isItemValid = false; d.status = action === 'pause' ? 'paused' : action === 'resume' ? 'downloading' : 'error';
      if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('download-status-changed', { id: d.id, status: d.status });
    } catch (err) { console.log(err); d.isItemValid = false; d.status = 'error'; }
  }
}
ipcMain.on('pause-download', (e, id) => dlAction(id, 'pause'));
ipcMain.on('resume-download', (e, id) => dlAction(id, 'resume'));
ipcMain.on('cancel-download', (e, id) => dlAction(id, 'cancel'));

ipcMain.on('retry-download', (e, data) => { if (data.url) session.defaultSession.downloadURL(data.url); });
ipcMain.on('remove-download', (e, id) => { const i = downloads.findIndex(d => d.id === id); if (i !== -1) { downloads.splice(i, 1); if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('download-removed', { id }); } });

// v2 安全加固：open-file/open-folder 限制为下载目录内
function inDownloads(fp) {
  try { const dd = path.resolve(app.getPath('downloads')); const r = path.resolve(fp); return r.startsWith(dd + path.sep) || r === dd; } catch { return false; }
}
ipcMain.on('open-file', (e, fp) => { if (fsSync.existsSync(fp) && inDownloads(fp)) shell.openPath(fp); else console.log('open-file拒绝:', fp); });
ipcMain.on('open-folder', (e, fp) => { if (fsSync.existsSync(fp) && inDownloads(fp)) shell.showItemInFolder(fp); else console.log('open-folder拒绝:', fp); });

ipcMain.on('clear-downloads', (e) => {
  downloads = []; currentDownloadInfo = null;
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('downloads-cleared');
    setTimeout(() => { if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('clear-downloads-success', '下载列表已清空'); }, 100);
  }
});

ipcMain.handle('get-current-tab', () => {
  if (tabs.length > 0 && currentTabIndex >= 0) { const t = tabs[currentTabIndex]; return { id: t.id, url: t.url, title: t.title, favicon: t.favicon, isLoading: t.isLoading }; }
  return null;
});
ipcMain.handle('get-all-tabs', () => tabs.map(t => ({ id: t.id, url: t.url, title: t.title, favicon: t.favicon, isLoading: t.isLoading })));
ipcMain.on('close-current-tab', () => { if (tabs.length > 0) closeTab(currentTabIndex); });
ipcMain.on('create-tab', (e, url) => createNewTab(url));

ipcMain.on('show-more-options-menu', (e, pos) => {
  const menu = new Menu();
  let zl = 1.0;
  if (tabs.length > 0 && currentTabIndex >= 0 && tabs[currentTabIndex].view) zl = tabs[currentTabIndex].view.webContents.getZoomLevel();
  const zp = Math.round(Math.pow(1.2, zl) * 100);
  menu.append(new MenuItem({ label: `重置缩放 (当前: ${zp}%)`, click: () => { if (tabs.length > 0 && currentTabIndex >= 0 && tabs[currentTabIndex].view) tabs[currentTabIndex].view.webContents.setZoomLevel(0); } }));
  menu.append(new MenuItem({ label: '放大', click: () => { if (tabs.length > 0 && currentTabIndex >= 0 && tabs[currentTabIndex].view) { const v = tabs[currentTabIndex].view.webContents.getZoomLevel(); tabs[currentTabIndex].view.webContents.setZoomLevel(v + 0.5); } } }));
  menu.append(new MenuItem({ label: '缩小', click: () => { if (tabs.length > 0 && currentTabIndex >= 0 && tabs[currentTabIndex].view) { const v = tabs[currentTabIndex].view.webContents.getZoomLevel(); tabs[currentTabIndex].view.webContents.setZoomLevel(v - 0.5); } } }));
  menu.append(new MenuItem({ type: 'separator' }));
  menu.popup({ window: mainWindow, x: pos.x, y: pos.y });
});

function createContextMenu(type, text = '') {
  const menu = new Menu();
  if (type === 'selection') {
    if (text) { menu.append(new MenuItem({ label: '复制', click: () => { if (mainWindow && mainWindow.webContents) mainWindow.webContents.copy(); } })); menu.append(new MenuItem({ type: 'separator' })); }
    menu.append(new MenuItem({ label: '主页', click: () => { if (tabs.length > 0 && currentTabIndex >= 0) { tabs[currentTabIndex].url = 'cosy://newtab'; loadTabContent(tabs[currentTabIndex]); } } }));
    menu.append(new MenuItem({ label: '设置', click: () => createNewTab('cosy://setting') }));
    menu.append(new MenuItem({ type: 'separator' }));
    menu.append(new MenuItem({ label: '开发者工具', click: () => { if (tabs.length > 0 && currentTabIndex >= 0 && tabs[currentTabIndex].view) tabs[currentTabIndex].view.webContents.toggleDevTools(); } }));
  } else {
    menu.append(new MenuItem({ label: '开发者工具', click: () => { if (tabs.length > 0 && currentTabIndex >= 0 && tabs[currentTabIndex].view) tabs[currentTabIndex].view.webContents.toggleDevTools(); } }));
    menu.append(new MenuItem({ label: '返回主页', click: () => { if (tabs.length > 0 && currentTabIndex >= 0) { tabs[currentTabIndex].url = 'cosy://newtab'; loadTabContent(tabs[currentTabIndex]); } } }));
    menu.append(new MenuItem({ label: '设置', click: () => createNewTab('cosy://setting') }));
  }
  return menu;
}

const userDataPath = path.join(os.homedir(), 'AppData', 'Roaming', 'OpenCosy', 'browser', 'userdata');
const extensionsPath = path.join(userDataPath, 'extensions');
const configPath = path.join(extensionsPath, 'config.json');

async function ensureDirs() { try { await fs.mkdir(userDataPath, { recursive: true }); await fs.mkdir(extensionsPath, { recursive: true }); } catch (e) { console.error(e); } }
async function readExtConfig() { try { await ensureDirs(); if (fsSync.existsSync(configPath)) return JSON.parse(await fs.readFile(configPath, 'utf8')); } catch (e) { console.error(e); } return { extensions: [] }; }
async function saveExtConfig(c) { try { await ensureDirs(); await fs.writeFile(configPath, JSON.stringify(c, null, 2)); return true; } catch (e) { console.error(e); return false; } }
async function validateExt(fp) {
  try {
    const mp = path.join(fp, 'manifest.json');
    if (!fsSync.existsSync(mp)) return { valid: false, error: '未找到manifest.json' };
    const m = JSON.parse(await fs.readFile(mp, 'utf8'));
    if (!m.name) return { valid: false, error: '缺少name' };
    if (!m.version) return { valid: false, error: '缺少version' };
    if (!m.manifest_version) return { valid: false, error: '缺少manifest_version' };
    return { valid: true, manifest: m };
  } catch (e) { return { valid: false, error: e.message }; }
}
async function copyExt(src, id) {
  try {
    const dst = path.join(extensionsPath, id); await fs.mkdir(dst, { recursive: true });
    for (const f of await fs.readdir(src)) {
      const sf = path.join(src, f), df = path.join(dst, f);
      if ((await fs.stat(sf)).isDirectory()) await copyExt(sf, path.join(id, f));
      else await fs.copyFile(sf, df);
    }
    return true;
  } catch (e) { console.error(e); return false; }
}
async function loadEnabledExtensions() { try { const c = await readExtConfig(); for (const e of c.extensions) if (e.enabled) await loadExt(e); } catch (e) { console.error(e); } }
async function loadExt(e) { try { const p = path.join(extensionsPath, e.id); if (fsSync.existsSync(p)) { await session.defaultSession.loadExtension(p); console.log('插件加载:', e.name); } } catch (err) { console.error(err); } }
async function unloadExt(id) { try { for (const e of session.defaultSession.getAllExtensions()) if (e.id === id) { await session.defaultSession.removeExtension(id); break; } } catch (e) { console.error(e); } }

ipcMain.handle('add-extension', async (e, fp) => {
  try {
    const v = await validateExt(fp); if (!v.valid) return { success: false, error: v.error };
    const id = `${v.manifest.name.replace(/[^a-zA-Z0-9]/g, '_')}_${v.manifest.version}`;
    const c = await readExtConfig();
    if (c.extensions.find(x => x.id === id)) return { success: false, error: '插件已存在' };
    if (!await copyExt(fp, id)) return { success: false, error: '复制失败' };
    let icon = '';
    if (v.manifest.icons) { const sz = Object.keys(v.manifest.icons).sort((a, b) => parseInt(b) - parseInt(a)); if (sz.length) icon = path.join(extensionsPath, id, v.manifest.icons[sz[0]]); }
    const ne = { id, name: v.manifest.name, version: v.manifest.version, description: v.manifest.description || '', icon, path: path.join(extensionsPath, id), enabled: true, addedDate: new Date().toISOString() };
    c.extensions.push(ne); if (!await saveExtConfig(c)) return { success: false, error: '保存失败' };
    return { success: true, extension: ne };
  } catch (err) { return { success: false, error: err.message }; }
});
ipcMain.handle('get-extensions', async () => { try { const c = await readExtConfig(); return { success: true, extensions: c.extensions }; } catch (e) { return { success: false, error: e.message, extensions: [] }; } });
ipcMain.handle('toggle-extension', async (e, { id, enabled }) => {
  try { const c = await readExtConfig(); const x = c.extensions.find(e => e.id === id); if (!x) return { success: false, error: '未找到' }; x.enabled = enabled; if (!await saveExtConfig(c)) return { success: false, error: '保存失败' }; return { success: true }; } catch (err) { return { success: false, error: err.message }; }
});
ipcMain.handle('remove-extension', async (e, id) => {
  try { const c = await readExtConfig(); const i = c.extensions.findIndex(e => e.id === id); if (i === -1) return { success: false, error: '未找到' }; await unloadExt(id); const p = path.join(extensionsPath, id); if (fsSync.existsSync(p)) await fs.rm(p, { recursive: true, force: true }); c.extensions.splice(i, 1); if (!await saveExtConfig(c)) return { success: false, error: '保存失败' }; return { success: true }; } catch (err) { return { success: false, error: err.message }; }
});
ipcMain.handle('browse-folder', async () => {
  try { const r = await dialog.showOpenDialog(mainWindow, { title: '选择插件文件夹', properties: ['openDirectory'] }); if (!r.canceled && r.filePaths.length) return { success: true, path: r.filePaths[0] }; return { success: false, error: '取消' }; } catch (e) { return { success: false, error: e.message }; }
});
ipcMain.on('show-context-menu', (e, type, text) => createContextMenu(type, text).popup());
ipcMain.on('save-settings', (e, s) => { try { fsSync.writeFileSync(path.join(app.getPath('userData'), 'cosySettings.json'), JSON.stringify(s, null, 2), 'utf-8'); e.reply('settings-saved', { success: true }); } catch (err) { console.error(err); e.reply('settings-saved', { success: false, error: err.message }); } });
ipcMain.on('update-theme-color', (e, color) => { if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('update-theme-color', color); tabs.forEach(t => { if (t.view && t.view.webContents) t.view.webContents.send('update-theme-color', color); }); });
ipcMain.on('get-settings', (e) => { try { const p = path.join(app.getPath('userData'), 'cosySettings.json'); if (fsSync.existsSync(p)) e.reply('settings-loaded', JSON.parse(fsSync.readFileSync(p, 'utf-8'))); else e.reply('settings-loaded', {}); } catch (err) { console.error(err); e.reply('settings-loaded', {}); } });
ipcMain.on('export-config', async (e, content) => {
  try { const r = await dialog.showSaveDialog(mainWindow, { title: '导出配置', defaultPath: 'cosy_config.inf', filters: [{ name: '配置文件', extensions: ['inf'] }, { name: '所有文件', extensions: ['*'] }] }); if (!r.canceled && r.filePath) { fsSync.writeFileSync(r.filePath, content, 'utf-8'); e.reply('export-config-success', '导出成功'); } else e.reply('export-config-canceled', '已取消'); } catch (err) { console.error(err); e.reply('export-config-error', err.message); }
});
