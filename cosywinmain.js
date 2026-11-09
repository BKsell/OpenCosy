let d = {};
function bindDeps(x) {
  d = x;
  require('./cosywinmain_part2').bindDeps(x);
}

function getTabLayout() {
  // 复用统一的有界设置读取（坏 / 超大文件回落 {}），不再各自 existsSync+parse。
  const settings = d.readStoredSettings();
  return settings.tabLayout || 'horizontal';
}

function getDefaultTabUrl() {
  const settings = d.readStoredSettings();
  if (settings.defaultTab === 'bing') return 'https://www.bing.com';
  if (settings.defaultTab === 'custom' && settings.customUrl && d.isSafeUrl(settings.customUrl))
    return settings.customUrl;
  return 'cosy://newtab';
}

function createWindow() {
  return require('./windowfactory').createWindow(d.createWindowCtx, );
}

function registerShortcuts() {
  return require('./shortcutrouter').registerShortcuts(d.registerShortcutsCtx, );
}

function getUrlProtocol(url) {
  // safeProtocol 默认解析失败回 null，与历史实现逐字一致。
  return d.urlResolve.safeProtocol(url);
}

function openTaskManagerTab() {
  const existing = d.tabs.findIndex(t => t && t.url === d.TASK_MANAGER_URL);
  if (existing >= 0) {
    if (existing !== d.currentTabIndex) d.switchToTab(existing);
    return d.tabs[existing];
  }
  return d.createNewTab(d.TASK_MANAGER_URL);
}

function openTabOverviewTab() {
  const existing = d.tabs.findIndex(t => t && t.url === d.TAB_OVERVIEW_URL);
  if (existing >= 0) {
    if (existing !== d.currentTabIndex) d.switchToTab(existing);
    return d.tabs[existing];
  }
  return d.createNewTab(d.TAB_OVERVIEW_URL);
}

function showErrorPage(tab, errorCode, errorDescription, validatedURL) {
  const errorParams = new URLSearchParams({
    code: d.getHttpStatusCode(errorCode),
    message: d.getErrorMessage(errorCode),
    reason: errorDescription,
    url: validatedURL,
    browserCode: errorCode,
    browserMessage: d.getBrowserErrorText(errorCode)
  });
  const errorUrl = `file://${__dirname}/src/error.html?${errorParams.toString()}`;
  tab.view.webContents.loadURL(errorUrl);
  tab.url = validatedURL;
  tab.title = `错误 - ${d.getHttpStatusCode(errorCode)}`;
  d.sendToRenderer('tab-updated', { id: tab.id, url: validatedURL, title: tab.title });
}

function pushNavState(tab) {
  if (!tab?.view?.webContents) return;
  tab.canGoBack = tab.view.webContents.canGoBack();
  tab.canGoForward = tab.view.webContents.canGoForward();
  d.sendToRenderer('tab-history-changed', {
    id: tab.id, canGoBack: tab.canGoBack, canGoForward: tab.canGoForward
  });
}

module.exports = Object.assign({}, require('./cosywinmain_part2'), {
  bindDeps,
  getTabLayout,
  getDefaultTabUrl,
  createWindow,
  registerShortcuts,
  getUrlProtocol,
  openTaskManagerTab,
  openTabOverviewTab,
  showErrorPage,
  pushNavState,
});
