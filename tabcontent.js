'use strict';

const { app, BrowserWindow, WebContentsView, ipcMain, session, protocol, Menu, MenuItem, dialog, shell, globalShortcut, clipboard, net, nativeTheme, webContents, safeStorage } = require('electron');
const inpageGuard = require('./inpageguard');
const menuGuard = require('./menuguard');
const path = require('path');
const popupGuard = require('./popupguard');
const searchProvider = require('./searchprovider');
const titleGuard = require('./titleguard');
const winPolicy = require('./winpolicy');

function loadTabContent(ctx, tab) {
  const {
    CONFIRMABLE_EXTERNAL_SCHEMES,
    addToHistory,
    addToReadingList,
    allowPopupForTab,
    applySavedZoom,
    bookmarks: readBookmarks,
    classifyFrameNavigation,
    createNewTab,
    getContentsState,
    getHttpStatusCode,
    getUrlProtocol,
    handleRenderProcessGone,
    history: readHistory,
    inpageStates,
    isDev,
    isSafeUrl,
    launchExternalWithPrompt,
    maybeFallbackAfterUpgradeFailure,
    originOfContents,
    pushNavState,
    recordSecurityEvent,
    searchProviderId: readSearchProviderId,
    sendToRenderer,
    showCosyError,
    showErrorPage,
    spellcheckEnabled: readSpellcheckEnabled,
    switchToTab,
    tabs: readTabs,
    titleStates,
    toggleDevTools,
    updateBrowserViewBounds,
  } = ctx;
  if (!tab.view) {
    // 标签视图与主窗口共用同一份 webPreferences 安全基线，杜绝两处配置漂移。
    const tabWinReview = winPolicy.harden({
      preload: path.join(__dirname, 'preload.js'),
      spellcheck: true,
    }, { preloadRoots: __dirname, requirePreload: true });
    if (winPolicy.hasCritical(tabWinReview.findings)) {
      for (const f of tabWinReview.findings.filter(x => x.severity === 'critical')) {
        try { recordSecurityEvent('window-policy', 'critical', `标签视图配置被拒绝: ${f.key}`, ''); } catch {}
      }
    }
    tab.view = new WebContentsView({
      webPreferences: tabWinReview.prefs
    });

    mainWindow.contentView.addChildView(tab.view);
    updateBrowserViewBounds();

    tab.view.webContents.setWindowOpenHandler(({ url, disposition }) => {
      // 页面用 window.open 唤起 mailto/tel 时不弹窗（没有新窗口的位置），
      // 直接走外部协议确认流；其它非 Web 协议照旧拒绝。
      const extScheme = normalizeExternalScheme(url);
      if (CONFIRMABLE_EXTERNAL_SCHEMES.has(extScheme)) {
        launchExternalWithPrompt(url, originOfContents(tab.view.webContents), true);
        return { action: 'deny' };
      }
      // 弹窗上下文额外拦截 javascript:/data:/vbscript:/file: 目标——这些协议在
      // 顶层地址栏另有处理，但绝不应在新浏览上下文里渲染/执行。
      const popupDecision = popupGuard.decidePopup({
        currentUrl: tab.url || '', targetUrl: url, disposition,
      });
      if (popupDecision.action === 'block') {
        recordSecurityEvent('popup-blocked', 'warn',
          `拦截危险协议弹窗: ${url}`, originOfContents(tab.view.webContents));
        sendToRenderer('popup-blocked', { url });
        return { action: 'deny' };
      }
      if (!isSafeUrl(url)) return { action: 'deny' };
      if (disposition === 'new-window' || disposition === 'foreground-tab') {
        // 弹窗轰炸限流：短时间内同一标签狂开窗口时拦截，只放行正常节奏的新窗口。
        if (!allowPopupForTab(tab.id)) {
          sendToRenderer('popup-blocked', { url });
          return { action: 'deny' };
        }
        const newTab = createNewTab(url);
        switchToTab(readTabs().indexOf(newTab));
      } else {
        tab.url = url;
        tab.view.webContents.loadURL(url);
      }
      return { action: 'deny' };
    });

    tab.view.webContents.on('will-navigate', (event, navigationUrl) => {
      // 外部协议 / 危险协议的拦截与确认由全局 web-contents 钩子统一处理
      // （否则这里和全局各弹一次确认框）；这里只负责窗内导航的状态同步。
      if (classifyFrameNavigation(navigationUrl, true) !== 'in-pane') {
        event.preventDefault();
        return;
      }
      tab.url = navigationUrl;
      addToHistory(navigationUrl, tab.title);
      sendToRenderer('tab-updated', { id: tab.id, url: navigationUrl });
    });

    tab.view.webContents.on('did-navigate', () => { pushNavState(tab); applySavedZoom(tab); });
    tab.view.webContents.on('did-navigate-in-page', (inEvent, inPageUrl) => {
      // pushState/replaceState 洪泛与畸形 URL 收口：拒绝 / 冷却 / 重复地址时不压历史、
      // 不更新地址栏，避免历史劫持与广播风暴；主导航 did-navigate 会清零配额。
      const st = getContentsState(inpageStates, tab.view.webContents.id, inpageGuard.createInPageState);
      const v = inpageGuard.decideInPageNav(st, inPageUrl || tab.url, Date.now());
      if (v.decision === inpageGuard.INPAGE_REJECT) {
        recordSecurityEvent('inpage-flood', 'warn',
          inpageGuard.describeInPageReason(v.reason), tab.url);
        return;
      }
      if (v.decision === inpageGuard.INPAGE_HOLD && v.reason === inpageGuard.HOLD_BURST) {
        recordSecurityEvent('inpage-flood', 'warn',
          inpageGuard.describeInPageReason(v.reason), tab.url);
        return;
      }
      if (v.decision === inpageGuard.INPAGE_HOLD) return; // 重复地址/冷却：静默合并
      pushNavState(tab);
      applySavedZoom(tab);
    });
    tab.view.webContents.on('dom-ready', () => applySavedZoom(tab));

    tab.view.webContents.on('did-redirect-navigation', (event, url) => {
      if (!isSafeUrl(url)) return;
      tab.url = url;
      sendToRenderer('tab-updated', { id: tab.id, url });
    });

    tab.view.webContents.on('page-title-updated', (event, rawTitle) => {
      // 标题由页面完全控制：净化控制字符 / 折叠空白 / 代码点安全截断，并对高频翻转与
      // 极短重复上报做收敛，防止伪加载闪烁、标题注入以及 addToHistory+IPC 广播风暴。
      const tst = getContentsState(titleStates, tab.view.webContents.id, titleGuard.createTitleState);
      const tv = titleGuard.decideTitleUpdate(tst, rawTitle, Date.now());
      if (tv.decision === titleGuard.TITLE_HOLD) return;
      const title = tv.title;
      tab.title = title;
      addToHistory(tab.url, title);
      sendToRenderer('tab-updated', { id: tab.id, title });
      if (tv.sanitized) {
        recordSecurityEvent('title-abuse', 'info',
          titleGuard.describeTitleReason(titleGuard.TITLE_SANITIZED), tab.url);
      }
    });

    tab.view.webContents.on('did-start-loading', () => {
      tab.isLoading = true;
      sendToRenderer('tab-loading', { id: tab.id, loading: true });
    });

    tab.view.webContents.on('did-stop-loading', () => {
      tab.isLoading = false;
      sendToRenderer('tab-loading', { id: tab.id, loading: false });
    });

    // 音频播放状态变化：Electron 此事件不带状态参数，需主动查询
    // isCurrentlyAudible / isAudioMuted，再广播给渲染进程显示喇叭图标。
    tab.view.webContents.on('audio-state-changed', () => {
      try {
        tab.audible = !!tab.view.webContents.isCurrentlyAudible();
        tab.muted = !!tab.view.webContents.isAudioMuted();
      } catch {
        return;
      }
      sendToRenderer('tab-audio-changed', { id: tab.id, audible: tab.audible, muted: tab.muted });
    });

    tab.view.webContents.on('did-fail-load', (event, errorCode, errorDescription, validatedURL, isMainFrame) => {
      if (!isMainFrame) return;
      // ERR_ABORTED(-3) 不是真失败：下载触发的导航、用户手动取消、被 window.open
      // 拦截或重定向链中止都会带这个码，此时弹错误页只会把正常页面盖掉。
      if (errorCode === -3) return;
      const httpStatus = getHttpStatusCode(errorCode);
      if (httpStatus === '403' && !tab.retry403) {
        tab.retry403 = true;
        tab.view.webContents.loadURL(validatedURL).catch(() => {
          showErrorPage(tab, errorCode, errorDescription, validatedURL);
        });
        return;
      }
      // HTTPS-Only 升级后对端没有可用 TLS：先给用户知情回退（确认后按站点记住
      // HTTP 例外）。用户选择留在错误页、或不属于可回退错误码时，才显示通用错误页。
      if (maybeFallbackAfterUpgradeFailure(tab, errorCode, validatedURL)) return;
      showErrorPage(tab, errorCode, errorDescription, validatedURL);
    });

    tab.view.webContents.on('render-process-gone', (event, details) => {
      handleRenderProcessGone(tab, details);
    });

    tab.view.webContents.on('page-favicon-updated', (event, favicons) => {
      // 图标数组同样来自页面：限制数量与单个长度、只放行 http(s)/data，防止喂入超大
      // data: URL 或 file:/blob:/javascript: 来源；取净化后的第一个作为标签图标。
      const { favicons: safe, dropped } = titleGuard.sanitizeFavicons(favicons);
      if (dropped > 0) {
        recordSecurityEvent('title-abuse', 'info',
          `网站图标包含 ${dropped} 个非法或超长条目，已过滤`, tab.url);
      }
      if (safe.length === 0) return;
      const faviconUrl = titleGuard.resolveFaviconHref(safe[0], tab.url);
      if (faviconUrl && titleGuard.isAllowedFaviconScheme(faviconUrl)) {
        tab.favicon = faviconUrl;
        sendToRenderer('tab-updated', { id: tab.id, favicon: tab.favicon });
      }
    });

    tab.view.webContents.on('context-menu', (event, params) => {
      // r33：菜单入参完全来自网页，先经 menuguard 统一净化（危险链接协议、超长 /
      // 含 CR/LF 的选中文本、非法错词与超长建议），后续一律只用净化后的值建菜单，
      // 杜绝畸形 label 折行伪造条目与持久拼写词典投毒。
      const mp = menuGuard.evaluateContextMenu(params);
      if (mp.reasons.length > 0) {
        recordSecurityEvent('context-menu-sanitized', 'info',
          `右键菜单参数已净化（${mp.reasons.join('；')}）`, originOfContents(tab.view.webContents));
      }
      const menu = new Menu();
      // 拼写建议放在菜单最顶部，与 Chromium 浏览器一致。
      // misspelledWord / suggestions 已逐条校验，建议不离开本机。
      if (readSpellcheckEnabled() && mp.isEditable && mp.misspelledWord) {
        if (mp.suggestions.length) {
          for (const word of mp.suggestions) {
            menu.append(new MenuItem({
              label: word,
              click: () => tab.view.webContents.replaceMisspelling(word)
            }));
          }
        } else {
          menu.append(new MenuItem({ label: '（无拼写建议）', enabled: false }));
        }
        menu.append(new MenuItem({
          label: '添加到词典',
          click: () => {
            try {
              // mp.misspelledWord 已确认是合法单词（无空白 / 控制字符 / 标记符）。
              tab.view.webContents.session.addWordToSpellCheckerDictionary(mp.misspelledWord);
            } catch (e) {
              console.error('添加自定义词典失败:', e);
            }
          }
        }));
        menu.append(new MenuItem({ type: 'separator' }));
      }
      if (mp.canUseLink && mp.linkUrl) {
        menu.append(new MenuItem({ label: '在新标签页中打开', click: () => createNewTab(mp.linkUrl) }));
        menu.append(new MenuItem({
          label: '加入稍后读',
          click: () => addToReadingList(mp.linkUrl, mp.selectionText || '')
        }));
        menu.append(new MenuItem({ label: '复制链接地址', click: () => clipboard.writeText(mp.linkUrl) }));
        menu.append(new MenuItem({ type: 'separator' }));
      }
      if (mp.hasSelection) {
        menu.append(new MenuItem({ label: '复制', role: 'copy' }));
        menu.append(new MenuItem({
          label: '搜索所选内容',
          click: () => {
            // r56：搜索动作跟随用户选择的默认搜索引擎（内核级模板白名单校验），
            // 不再写死 Bing，也不接受 renderer 传入的模板。
            const url = searchProvider.buildSearchUrl(readSearchProviderId(), mp.selectionText);
            createNewTab(url || ('https://www.bing.com/search?q=' + encodeURIComponent(mp.selectionText)));
          }
        }));
      }
      if (mp.hasSelection && mp.isEditable) menu.append(new MenuItem({ label: '剪切', role: 'cut' }));
      if (mp.isEditable) menu.append(new MenuItem({ label: '粘贴', role: 'paste' }));
      if (mp.isEditable) menu.append(new MenuItem({ label: '全选', role: 'selectAll' }));
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
        'sitedata': 'src/sitedata.html',
        'permissions': 'src/permissions.html',
        'security': 'src/security.html',
        'hashes': 'src/hashes.html',
        'download': 'src/download', 'downloadlist': 'src/downloadlist.html',
        'taskmanager': 'src/taskmanager.html',
        'taboverview': 'src/taboverview.html',
        'history': 'src/history.html',
        'bookmarks': 'src/bookmarks.html',
        'readinglist': 'src/readinglist.html',
        'about': 'src/about.html',
        'shortcuts': 'src/shortcuts.html',
        'pages': 'src/pages.html',
        'reader': 'src/reader.html',
        'httpsonly': 'src/httpsonly.html',
        'blockrules': 'src/blockrules.html'
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

module.exports = { loadTabContent };
