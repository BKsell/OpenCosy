'use strict';

const { app, BrowserWindow, WebContentsView, ipcMain, session, protocol, Menu, MenuItem, dialog, shell, globalShortcut, clipboard, net, nativeTheme, webContents, safeStorage } = require('electron');
const path = require('path');
const winPolicy = require('./winpolicy');

function createWindow(ctx, ) {
  const {
    DEFAULT_WINDOW_HEIGHT,
    DEFAULT_WINDOW_WIDTH,
    MIN_WINDOW_HEIGHT,
    MIN_WINDOW_WIDTH,
    clearOnExit: readClearOnExit,
    clearSession,
    clearStoredPins,
    clearStoredTabGroups,
    confirmCloseMultiple: readConfirmCloseMultiple,
    createNewTab,
    downloads: readDownloads,
    ensurePinnedTabsOpened,
    setFileToOpen,
    getDefaultTabUrl,
    getTabLayout,
    isSafeUrl,
    loadSession,
    purgeBrowsingDataOnExit,
    recordSecurityEvent,
    registerShortcuts,
    rehydrateTabGroups,
    savePinsNow,
    saveSession,
    saveTabGroupsNow,
    tabs: readTabs,
    updateBrowserViewBounds,
  } = ctx;
  if (mainWindow && !mainWindow.isDestroyed()) return;

  // 主窗口 webPreferences 走统一安全基线（winpolicy）：强制关闭 Node 集成 /
  // 开启上下文隔离与沙箱 / 开启同源策略，并校验 preload 必须在应用目录内。
  const mainWinReview = winPolicy.harden({
    preload: path.join(__dirname, 'preload.js'),
    spellcheck: true,
  }, { preloadRoots: __dirname, requirePreload: true });
  if (winPolicy.hasCritical(mainWinReview.findings)) {
    for (const f of mainWinReview.findings.filter(x => x.severity === 'critical')) {
      try { recordSecurityEvent('window-policy', 'critical', `主窗口配置被拒绝: ${f.key}`, ''); } catch {}
    }
  }
  mainWindow = new BrowserWindow({
    width: DEFAULT_WINDOW_WIDTH, height: DEFAULT_WINDOW_HEIGHT,
    minWidth: MIN_WINDOW_WIDTH, minHeight: MIN_WINDOW_HEIGHT,
    webPreferences: mainWinReview.prefs,
    titleBarStyle: 'hidden', frame: false, show: false,
    icon: path.join(__dirname, 'ico.png')
  });

  const tabLayout = getTabLayout();
  const htmlFile = tabLayout === 'vertical' ? 'src/index_vertical.html' : 'src/index.html';
  mainWindow.loadFile(htmlFile);

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    if (readFileToOpen()) {
      createNewTab(readFileToOpen());
      setFileToOpen(null);
    } else {
      const savedSession = loadSession();
      if (savedSession && savedSession.length > 0) {
        savedSession.forEach((tab) => createNewTab(tab.url));
        clearSession();
      } else {
        createNewTab(getDefaultTabUrl());
      }
      // 固定标签独立持久化：会话恢复后补开缺失的固定页并重水合固定态。
      ensurePinnedTabsOpened();
      // 标签分组独立持久化：会话恢复后按本次打开的标签重水合分组并重排标签栏。
      rehydrateTabGroups();
    }
  });

  mainWindow.on('resize', updateBrowserViewBounds);
  mainWindow.on('move', updateBrowserViewBounds);
  mainWindow.once('closed', () => {
    // 开启了“退出时清除浏览数据”就不要把本次标签会话落盘，避免下次又恢复出来。
    if (!readClearOnExit()) {
      saveSession();
      // 同步写一次固定标签，防抖定时器在退出时可能来不及触发。
      savePinsNow();
      // 同步写一次标签分组，防抖定时器在退出时可能来不及触发。
      saveTabGroupsNow();
    } else {
      clearStoredPins();
      clearStoredTabGroups();
    }
    mainWindow = null;
  });

  // 会话原先只在正常退出时落盘，一旦进程崩溃 / 被任务管理器结束，下次启动就
  // 无法恢复标签。这里周期性自动保存一次，崩溃最多丢失这 15 秒内新开/关闭的标签。
  const SESSION_AUTOSAVE_MS = 15000;
  const sessionAutosaveTimer = setInterval(() => {
    try { if (!readClearOnExit()) saveSession(); } catch {}
  }, SESSION_AUTOSAVE_MS);
  if (typeof sessionAutosaveTimer.unref === 'function') sessionAutosaveTimer.unref();

  // 关闭窗口时按顺序做两道确认，再按设置执行隐私清理：
  // 1) 开了“多标签退出确认”且仍有多个标签 → 二次确认；
  // 2) 有关键下载进行中 → 放弃下载确认；
  // 3) 开了“退出时清除浏览数据”→ 清理完成后才真正退出。
  let allowQuitWithDownloads = false;
  let multiTabConfirmed = false;
  let exitPurged = false;
  mainWindow.on('close', async (e) => {
    if (!mainWindow) return;

    if (!multiTabConfirmed && readConfirmCloseMultiple() && readTabs().length > 1) {
      e.preventDefault();
      const choice = dialog.showMessageBoxSync(mainWindow, {
        type: 'question',
        buttons: ['取消', '全部关闭'],
        defaultId: 0,
        cancelId: 0,
        title: '关闭所有标签页？',
        message: `当前还有 ${tabs.length} 个标签页打开，确定要退出 OpenCosy 吗？`,
        detail: '退出将结束本次浏览会话。',
      });
      if (choice !== 1) return;
      multiTabConfirmed = true;
      mainWindow.close();
      return;
    }

    if (!allowQuitWithDownloads) {
      const active = readDownloads().some(d => d && (d.status === 'downloading' || d.status === 'pending' || d.status === 'paused'));
      if (active) {
        e.preventDefault();
        const choice = dialog.showMessageBoxSync(mainWindow, {
          type: 'warning',
          buttons: ['继续下载，留在窗口', '放弃下载并退出'],
          defaultId: 0,
          cancelId: 0,
          title: '仍有下载进行中',
          message: '当前还有未完成的下载，确定要退出吗？',
          detail: '退出后正在进行的下载会被中断，已完成的文件不受影响。',
        });
        if (choice === 1) {
          allowQuitWithDownloads = true;
          mainWindow.close();
        }
        return;
      }
    }

    if (readClearOnExit() && !exitPurged) {
      e.preventDefault();
      exitPurged = true;
      try {
        await purgeBrowsingDataOnExit();
      } catch (err) {
        console.error('退出时清除浏览数据失败:', err);
      }
      mainWindow.close();
    }
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (isSafeUrl(url)) createNewTab(url);
    return { action: 'deny' };
  });

  registerShortcuts();
}

module.exports = { createWindow };
