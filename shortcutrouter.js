'use strict';

const { app, BrowserWindow, WebContentsView, ipcMain, session, protocol, Menu, MenuItem, dialog, shell, globalShortcut, clipboard, net, nativeTheme, webContents, safeStorage } = require('electron');
const shortcutKeys = require('./shortcutkeys');

function registerShortcuts(ctx, ) {
  const {
    applyFind,
    bookmarks: readBookmarks,
    closeTab,
    createNewTab,
    createWindow,
    currentTabIndex: readCurrentTabIndex,
    discardAllBackgroundTabs,
    enterReaderMode,
    getCurrentTabWebContents,
    getLastClosedTab,
    goHome,
    history: readHistory,
    isSafeUrl,
    openTabOverviewTab,
    openTaskManagerTab,
    resetZoom,
    saveBookmarks,
    sendToRenderer,
    showOpenFileDialog,
    switchToTab,
    tabs: readTabs,
    toggleDevTools,
    toggleTabPinned,
    zoomIn,
    zoomOut,
  } = ctx;
  if (!mainWindow) return;
  mainWindow.webContents.on('before-input-event', (event, input) => {
    // 键位匹配（修饰键归一化、ctrl/meta 等价、优先级）全部收口到 shortcutkeys.js，
    // 这里只负责把动作 id 派发到对应处理函数，并与旧实现逐字等价地阻止默认行为。
    const action = shortcutKeys.matchShortcut(input);
    if (!action) return;
    switch (action) {
      case shortcutKeys.ACTION.NEW_TAB:
        createNewTab();
        event.preventDefault();
        break;
      case shortcutKeys.ACTION.REOPEN_CLOSED_TAB: {
        const lastClosedTab = getLastClosedTab();
        if (lastClosedTab) createNewTab(lastClosedTab.url);
        event.preventDefault();
        break;
      }
      case shortcutKeys.ACTION.CLOSE_TAB:
      case shortcutKeys.ACTION.CLOSE_TAB_F4:
        // Ctrl+W 与 Ctrl+F4 都是关闭当前标签页（多标签窗口惯例）
        closeTab(readCurrentTabIndex());
        event.preventDefault();
        break;
      case shortcutKeys.ACTION.NEW_WINDOW:
        createWindow();
        event.preventDefault();
        break;
      case shortcutKeys.ACTION.DUPLICATE_TAB: {
        const tab = readTabs()[readCurrentTabIndex()];
        if (tab && isSafeUrl(tab.url)) createNewTab(tab.url);
        event.preventDefault();
        break;
      }
      case shortcutKeys.ACTION.TOGGLE_BOOKMARKS_BAR:
        // Ctrl+Shift+B：切换书签栏（Chrome/Edge 惯例）
        sendToRenderer('toggle-bookmarks-bar');
        event.preventDefault();
        break;
      case shortcutKeys.ACTION.BOOKMARK_ALL_TABS: {
        // Ctrl+Shift+D：把所有打开的标签一键加为书签
        const newBookmarks = readTabs()
          .filter(t => isSafeUrl(t.url) && !t.url.startsWith('cosy://'))
          .map(t => ({ url: t.url, title: t.title, addedDate: new Date().toISOString() }))
          .filter(b => !readBookmarks().find(x => x.url === b.url));
        if (newBookmarks.length > 0) {
          readBookmarks().push(...newBookmarks);
          saveBookmarks();
          sendToRenderer('bookmarks-updated', readBookmarks());
          sendToRenderer('show-toast', `已收藏 ${newBookmarks.length} 个标签页`);
        } else {
          sendToRenderer('show-toast', '没有可收藏的标签页');
        }
        event.preventDefault();
        break;
      }
      case shortcutKeys.ACTION.DISCARD_BACKGROUND_TABS: {
        // Ctrl+Shift+S：立即释放所有后台标签内存（Memory Saver 手动触发）
        const n = discardAllBackgroundTabs();
        sendToRenderer('show-toast', n > 0 ? `已休眠 ${n} 个后台标签页` : '没有需要休眠的后台标签页');
        event.preventDefault();
        break;
      }
      case shortcutKeys.ACTION.NEXT_TAB:
        switchToTab((readCurrentTabIndex() + 1) % readTabs().length);
        event.preventDefault();
        break;
      case shortcutKeys.ACTION.PREV_TAB:
        switchToTab((readCurrentTabIndex() - 1 + readTabs().length) % readTabs().length);
        event.preventDefault();
        break;
      case shortcutKeys.ACTION.TOGGLE_PINNED_TAB: {
        // Alt+Shift+P：固定 / 取消固定当前标签。
        const cur = readTabs()[readCurrentTabIndex()];
        if (cur) {
          const r = toggleTabPinned(cur.id);
          if (r && r.success) {
            sendToRenderer('show-toast', r.pinned ? '已固定标签页' : '已取消固定标签页');
          }
        }
        event.preventDefault();
        break;
      }
      case shortcutKeys.ACTION.FOCUS_ADDRESS_BAR:
        // Ctrl+L / F6：聚焦地址栏（Chrome/Edge 惯例）
        mainWindow.webContents.send('focus-address-bar');
        event.preventDefault();
        break;
      case shortcutKeys.ACTION.FIND:
        mainWindow.webContents.send('show-find-bar');
        event.preventDefault();
        break;
      case shortcutKeys.ACTION.FIND_NEXT:
      case shortcutKeys.ACTION.FIND_PREV:
        // F3 / Ctrl+G：继续查找（Shift 反向），动作 id 已编码方向
        applyFind(action === shortcutKeys.ACTION.FIND_NEXT);
        event.preventDefault();
        break;
      case shortcutKeys.ACTION.OPEN_DOWNLOADS:
        createNewTab('cosy://downloadlist');
        event.preventDefault();
        break;
      case shortcutKeys.ACTION.PRINT: {
        const wc = getCurrentTabWebContents();
        if (wc) wc.print({ silent: false, printBackground: true });
        event.preventDefault();
        break;
      }
      case shortcutKeys.ACTION.VIEW_SOURCE: {
        const tab = readTabs()[readCurrentTabIndex()];
        if (tab && tab.view?.webContents && isSafeUrl(tab.url)) {
          tab.view.webContents.viewSource();
        }
        event.preventDefault();
        break;
      }
      case shortcutKeys.ACTION.OPEN_FILE:
        showOpenFileDialog();
        event.preventDefault();
        break;
      case shortcutKeys.ACTION.GO_HOME:
        goHome();
        event.preventDefault();
        break;
      case shortcutKeys.ACTION.RELOAD: {
        const wc = getCurrentTabWebContents();
        if (wc) wc.reload();
        event.preventDefault();
        break;
      }
      case shortcutKeys.ACTION.RELOAD_BYPASSING_CACHE: {
        const wc = getCurrentTabWebContents();
        if (wc) wc.reloadIgnoringCache();
        event.preventDefault();
        break;
      }
      case shortcutKeys.ACTION.TOGGLE_DEVTOOLS:
        toggleDevTools();
        event.preventDefault();
        break;
      case shortcutKeys.ACTION.OPEN_TASK_MANAGER:
        openTaskManagerTab();
        event.preventDefault();
        break;
      case shortcutKeys.ACTION.OPEN_TAB_OVERVIEW:
        openTabOverviewTab();
        event.preventDefault();
        break;
      case shortcutKeys.ACTION.ENTER_READER:
        enterReaderMode();
        event.preventDefault();
        break;
      case shortcutKeys.ACTION.EXIT_FULLSCREEN: {
        // 现代浏览器惯例：Esc 退出 HTML 全屏（仅在全屏时才拦截）
        const wc = getCurrentTabWebContents();
        if (wc && wc.isFullScreen()) {
          wc.exitFullScreen();
          event.preventDefault();
        }
        break;
      }
      case shortcutKeys.ACTION.ZOOM_IN:
        zoomIn();
        event.preventDefault();
        break;
      case shortcutKeys.ACTION.ZOOM_OUT:
        zoomOut();
        event.preventDefault();
        break;
      case shortcutKeys.ACTION.ZOOM_RESET:
        resetZoom();
        event.preventDefault();
        break;
      case shortcutKeys.ACTION.BACK: {
        const wc = getCurrentTabWebContents();
        if (wc?.canGoBack()) wc.goBack();
        event.preventDefault();
        break;
      }
      case shortcutKeys.ACTION.FORWARD: {
        const wc = getCurrentTabWebContents();
        if (wc?.canGoForward()) wc.goForward();
        event.preventDefault();
        break;
      }
      case shortcutKeys.ACTION.TOGGLE_BOOKMARK: {
        const tab = readTabs()[readCurrentTabIndex()];
        if (tab && isSafeUrl(tab.url) && !tab.url.startsWith('cosy://')) {
          const existing = readBookmarks().findIndex(b => b.url === tab.url);
          if (existing === -1) {
            readBookmarks().push({ url: tab.url, title: tab.title, addedDate: new Date().toISOString() });
            saveBookmarks();
            tab.bookmarked = true;
            sendToRenderer('bookmarks-updated', readBookmarks());
            sendToRenderer('show-toast', '已添加书签');
          } else {
            readBookmarks().splice(existing, 1);
            saveBookmarks();
            tab.bookmarked = false;
            sendToRenderer('bookmarks-updated', readBookmarks());
            sendToRenderer('show-toast', '已移除书签');
          }
        }
        event.preventDefault();
        break;
      }
      case shortcutKeys.ACTION.OPEN_HISTORY:
        mainWindow.webContents.send('show-history');
        event.preventDefault();
        break;
      case shortcutKeys.ACTION.OPEN_HISTORY_PAGE:
        createNewTab('cosy://history');
        event.preventDefault();
        break;
      case shortcutKeys.ACTION.OPEN_READING_LIST:
        createNewTab('cosy://readinglist');
        event.preventDefault();
        break;
      case shortcutKeys.ACTION.CLEAR_BROWSING_DATA:
        sendToRenderer('show-clear-data-dialog');
        event.preventDefault();
        break;
      default:
        break;
    }
  });
}

module.exports = { registerShortcuts };
