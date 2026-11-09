'use strict';

let d = {};

function bindDeps(next) {
  d = next;
}

function tabOverviewItem(tab, index) {
  const groupId = d.tabGroupModel.groupOf(tab.id);
  let groupName = '';
  let groupColor = '';
  if (groupId) {
    const g = d.tabGroupModel.getGroup(groupId);
    if (g) {
      groupName = String(g.title || '');
      groupColor = String(g.color || '');
    }
  }
  const wc = tab && tab.view && tab.view.webContents;
  return {
    id: String(tab.id),
    index,
    title: String(tab.title || tab.url || '未命名标签页').slice(0, 300),
    url: String(tab.url || '').slice(0, 1000),
    favicon: typeof tab.favicon === 'string' ? tab.favicon.slice(0, 1000) : '',
    active: index === d.currentTabIndex,
    pinned: !!tab.pinned,
    muted: !!tab.muted,
    crashed: !!tab.crashed,
    discarded: !!tab.discarded,
    groupId: groupId || '',
    groupName: groupName.slice(0, 60),
    groupColor: groupColor.slice(0, 40),
    alive: !!(wc && !wc.isDestroyed()),
  };
}

function closeTab(tabIndex) {
  if (tabIndex >= 0 && tabIndex < d.tabs.length) {
    const tab = d.tabs[tabIndex];
    // 单独关闭一个固定标签视为用户明确要去掉它：同步移出固定集合并落盘，
    // 否则下次启动会被固定清单按 URL 重新拉回。批量关闭从不包含固定标签，
    // 因此固定的长期页不会被“关闭其他/左侧/右侧”顺手清掉。
    if (tab.pinned) {
      d.pinModel.unpin(tab.id);
      tab.pinned = false;
      d.persistPins();
    }
    d.addToRecentlyClosed(tab);
    d.popupOpenTimes.delete(tab.id);
    // 标签分组同步：关闭的标签若在组内，移出成员；组因此变空则自动解散
    // （与 Chrome 一致：最后一个标签关闭后组消失）。
    d.tabGroupModel.onTabClosed(tab.id, true);
    if (tab.view) tab.view.webContents.destroy();
    d.tabs.splice(tabIndex, 1);
    if (d.tabs.length === 0) {
      createNewTab(d.getDefaultTabUrl());
      d.currentTabIndex = 0;
    } else if (d.currentTabIndex >= d.tabs.length) {
      d.currentTabIndex = d.tabs.length - 1;
    }
    if (d.tabs.length > 0) switchToTab(d.currentTabIndex);
    d.persistTabGroups();
    d.sendToRenderer('tab-closed', tabIndex);
  }
}

function switchToTab(tabIndex) {
  if (tabIndex >= 0 && tabIndex < d.tabs.length) {
    const prevContents = d.getCurrentTabWebContents();
    d.currentTabIndex = tabIndex;
    const tab = d.tabs[tabIndex];
    tab.lastActiveAt = Date.now();
    // 后台崩溃的标签在此刻才重建视图，避免坏页面在后台空转。
    if (tab.crashed) d.rebuildCrashedTab(tab);
    // 被内存节省休眠的标签切回时按原 URL 唤醒重载。
    if (tab.discarded) d.reloadDiscardedTab(tab);
    if (tab.view) {
      d.mainWindow.contentView.addChildView(tab.view);
      updateBrowserViewBounds();
    }
    d.sendToRenderer('tab-switched', { id: tab.id, index: tabIndex });
    d.pushNavState(tab);

    // 换标签时清掉旧标签上残留的查找高亮；若查找栏仍开着且有内容，
    // 在新标签上从头自动重查，保持“查找跟随当前标签”的浏览器惯例。
    const nextContents = d.getCurrentTabWebContents();
    if (prevContents && prevContents !== nextContents) {
      try { prevContents.stopFindInPage('clearSelection'); } catch (_) { /* 视图已销毁 */ }
    }
    if (d.findState.text && nextContents) d.applyFind(true);
  }
}

function createNewTab(url = 'cosy://newtab') {
  if (!d.isSafeUrl(url)) url = 'cosy://newtab';
  const tabId = Date.now().toString() + Math.random().toString(36).slice(2, 6);
  const tab = new Tab(tabId, url);

  if (d.getUrlProtocol(url) === 'cosy:') {
    tab.favicon = 'file://' + d.path.join(__dirname, 'ico.png');
  } else {
    tab.favicon = 'file://' + d.path.join(__dirname, 'src', 'loading.gif');
  }

  d.tabs.push(tab);
  d.currentTabIndex = d.tabs.length - 1;
  d.sendToRenderer('tab-created', { id: tab.id, url: tab.url, title: tab.title, favicon: tab.favicon, pinned: !!tab.pinned });
  d.loadTabContent(tab);
  d.sendToRenderer('tab-switched', { id: tab.id, index: d.currentTabIndex });
  setTimeout(updateBrowserViewBounds, 0);
  return tab;
}

function adjustCurrentZoom({ delta, factor: explicit } = {}) {
  const tab = d.tabs[d.currentTabIndex];
  if (!tab || !tab.view || !tab.view.webContents) return null;
  const wc = tab.view.webContents;
  const origin = d.originOfUrl(tab.url);
  let factor = 1;
  try { factor = wc.getZoomFactor(); } catch { factor = (origin && d.zoomFactorsByOrigin.get(origin)) || 1; }
  if (!Number.isFinite(factor) || factor <= 0) factor = 1;

  if (typeof explicit === 'number' && Number.isFinite(explicit)) {
    factor = explicit;
  } else if (delta === 'in') {
    factor *= 1.1;
  } else if (delta === 'out') {
    factor /= 1.1;
  }
  factor = clampZoomFactor(Math.round(factor * 1000) / 1000);
  wc.setZoomFactor(factor);
  if (origin) {
    d.zoomFactorsByOrigin.set(origin, factor);
    persistZoomFactors();
  }
  const percent = Math.round(factor * 100);
  // 通知渲染层显示缩放百分比浮层（对齐 Chrome 放大/缩小时的 OSD）。
  d.sendToRenderer('zoom-level-changed', { percent, factor });
  return { factor, percent };
}

function updateBrowserViewBounds() {
  if (d.tabs.length > 0 && d.currentTabIndex >= 0) {
    const tab = d.tabs[d.currentTabIndex];
    if (tab && tab.view) {
      const [width, height] = d.mainWindow.getSize();
      const tabLayout = d.getTabLayout();

      let x, y, w, h;
      if (tabLayout === 'vertical') {
        const tabBarWidth = d.isTabBarCollapsed ? d.COLLAPSED_TAB_BAR_WIDTH : d.DEFAULT_TAB_BAR_WIDTH_VERTICAL;
        x = tabBarWidth; y = 75; w = width - tabBarWidth; h = height - 75;
      } else {
        x = 0; y = d.DEFAULT_TAB_BAR_HEIGHT_HORIZONTAL; w = width; h = height - d.DEFAULT_TAB_BAR_HEIGHT_HORIZONTAL;
      }
      tab.view.setBounds({ x, y, width: w, height: h });
    }
  }
}

function clampZoomFactor(f) {
  if (!Number.isFinite(f)) return 1;
  return Math.min(d.MAX_ZOOM_FACTOR, Math.max(d.MIN_ZOOM_FACTOR, f));
}

function applySavedZoom(tab) {
  if (!tab || !tab.view || !tab.view.webContents) return;
  const origin = d.originOfUrl(tab.url);
  if (origin && d.zoomFactorsByOrigin.has(origin)) {
    tab.view.webContents.setZoomFactor(d.zoomFactorsByOrigin.get(origin));
  }
}

function resetZoom() {
  adjustCurrentZoom({ factor: 1 });
}

function zoomIn() {
  adjustCurrentZoom({ delta: 'in' });
}

function zoomOut() {
  adjustCurrentZoom({ delta: 'out' });
}

function persistZoomFactors() {
  if (d.zoomSaveTimer) clearTimeout(d.zoomSaveTimer);
  d.zoomSaveTimer = setTimeout(() => {
    try {
      const origins = {};
      for (const [origin, factor] of d.zoomFactorsByOrigin) origins[origin] = factor;
      d.ledgerStore.writeJSONStore(d.zoomStorePath, { version: 1, origins });
    } catch {}
  }, 400);
}

function loadZoomFactors() {
  try {
    // 有界读：缺失 / 损坏 / 被撑大的 zoom 台账回落 null，直接 return，不影响启动。
    const data = d.ledgerStore.readJSONStore(d.zoomStorePath, null);
    if (!data || typeof data !== 'object' || !data.origins || typeof data.origins !== 'object') return;
    for (const [origin, factor] of Object.entries(data.origins)) {
      if (typeof origin !== 'string' || !/^https?:|^cosy:/.test(origin)) continue;
      if (typeof factor !== 'number' || !Number.isFinite(factor)) continue;
      d.zoomFactorsByOrigin.set(origin, clampZoomFactor(factor));
      if (d.zoomFactorsByOrigin.size >= d.MAX_REMEMBERED_ORIGINS) break;
    }
  } catch {}
}

module.exports = { tabOverviewItem, closeTab, switchToTab, createNewTab, adjustCurrentZoom, updateBrowserViewBounds, clampZoomFactor, applySavedZoom, resetZoom, zoomIn, zoomOut, persistZoomFactors, loadZoomFactors, bindDeps };
