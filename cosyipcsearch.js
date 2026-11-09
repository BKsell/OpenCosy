'use strict';

let d = {};

function bindDeps(x) {
  d = x;
}

function registerFindIpc() {
d.ipcMain.on('find-in-page', (event, payload) => {
  if (!d.isMainSender(event)) return;
  const { text, forward, matchCase, wholeWord } = payload || {};
  // 输入与频率全部过 findguard：拒非字符串 / 超长 / 控制字符，合并极短重复提交，
  // 按键洪泛时进入短暂冷却，避免超长 query 匹配与 found-in-page 广播拖慢渲染进程。
  const v = d.findGuard.decideFind(
    d.findRateState,
    { text, matchCase: !!matchCase, wholeWord: !!wholeWord },
    Date.now()
  );
  if (v.decision === d.findGuard.FIND_REJECT) {
    const severity = (v.reason === d.findGuard.HOLD_BURST || v.reason === d.findGuard.HOLD_COOLDOWN)
      ? 'info' : 'warn';
    d.recordSecurityEvent('find-rate-limited', severity, d.findGuard.describeFindReason(v.reason), '');
    return;
  }
  const wc = d.getCurrentTabWebContents();
  if (v.decision === d.findGuard.FIND_SKIP_EMPTY) {
    d.findState = { text: '', matchCase: !!matchCase, wholeWord: !!wholeWord };
    if (wc) wc.stopFindInPage('clearSelection');
    return;
  }
  if (v.decision === d.findGuard.FIND_COALESCE) return;

  // 选项变化（区分大小写 / 整词）时重新开始查找，而不是沿用上一次的匹配位置。
  const optionsChanged = d.findState.matchCase !== v.matchCase || d.findState.wholeWord !== v.wholeWord;
  d.findState = { text: v.text, matchCase: v.matchCase, wholeWord: v.wholeWord };
  if (!wc) return;
  wc.findInPage(v.text, {
    forward: forward !== false,
    matchCase: v.matchCase,
    wholeWord: v.wholeWord,
    ...(optionsChanged ? { findNext: false } : {}),
  });
});

d.ipcMain.on('stop-find', (event) => {
  if (!d.isMainSender(event)) return;
  d.findState.text = '';
  // 结束查找时同时清掉去重指纹，允许用户重新打开查找栏查找同一个词。
  d.findGuard.resetFind(d.findRateState);
  const wc = d.getCurrentTabWebContents();
  if (wc) wc.stopFindInPage('clearSelection');
});

d.ipcMain.on('show-more-options-menu', (event, position) => {
  if (!d.isMainSender(event)) return;
  const menu = new d.Menu();
  const wc = d.getCurrentTabWebContents();
  const currentZoomLevel = wc ? wc.getZoomLevel() : 0;
  const currentZoomPercent = Math.round(Math.pow(1.2, currentZoomLevel) * 100);
  menu.append(new d.MenuItem({ label: `重置缩放 (当前: ${currentZoomPercent}%)`, click: d.resetZoom }));
  menu.append(new d.MenuItem({ label: '放大', click: d.zoomIn }));
  menu.append(new d.MenuItem({ label: '缩小', click: d.zoomOut }));
  menu.append(new d.MenuItem({ type: 'separator' }));
  menu.append(new d.MenuItem({
    label: '重新打开已关闭的标签页 (Ctrl+Shift+T)',
    click: () => {
      const lastClosedTab = d.getLastClosedTab();
      if (lastClosedTab) d.createNewTab(lastClosedTab.url);
    }
  }));
  menu.append(new d.MenuItem({ type: 'separator' }));
  menu.append(new d.MenuItem({
    label: '休眠所有后台标签页 (Ctrl+Shift+S)',
    enabled: d.memorySaverEnabled,
    click: () => {
      const n = d.discardAllBackgroundTabs();
      d.sendToRenderer('show-toast', n > 0 ? `已休眠 ${n} 个后台标签页` : '没有需要休眠的后台标签页');
    }
  }));
  const pos = position && Number.isFinite(position.x) && Number.isFinite(position.y)
    ? { x: Math.round(position.x), y: Math.round(position.y) }
    : null;
  menu.popup(pos ? { window: d.mainWindow, x: pos.x, y: pos.y } : { window: d.mainWindow });
});
}

function registerTabOverviewIpc() {
d.ipcMain.handle('tab-overview-snapshot', (event) => {
  if (!d.isTabOverviewFrameSender(event)) return { ok: false, error: 'denied' };
  return {
    ok: true,
    tabs: d.tabs.map(d.tabOverviewItem),
    groups: d.tabGroupModel.orderedGroupIds().map(gid => {
      const g = d.tabGroupModel.getGroup(gid);
      return {
        id: gid,
        name: g ? String(g.title || '') : '',
        color: g ? String(g.color || '') : '',
        collapsed: !!(g && g.collapsed),
      };
    }),
  };
});

// 概览页点击卡片：切到该标签。id 不存在时静默失败（标签可能已被关闭）。
d.ipcMain.handle('tab-overview-activate', (event, payload = {}) => {
  if (!d.isTabOverviewFrameSender(event)) return { ok: false, error: 'denied' };
  const id = payload && payload.id != null ? String(payload.id) : '';
  const index = d.tabs.findIndex(t => t && String(t.id) === id);
  if (index < 0) return { ok: false, error: 'not-found' };
  d.switchToTab(index);
  return { ok: true, id };
});

// 概览页关闭卡片：复用现有 closeTab（含分组联动 / 最近关闭 / 持久化）。
d.ipcMain.handle('tab-overview-close', (event, payload = {}) => {
  if (!d.isTabOverviewFrameSender(event)) return { ok: false, error: 'denied' };
  const id = payload && payload.id != null ? String(payload.id) : '';
  const index = d.tabs.findIndex(t => t && String(t.id) === id);
  if (index < 0) return { ok: false, error: 'not-found' };
  d.closeTab(index);
  return { ok: true, id };
});

// 概览页缩略图：capturePage 截当前标签画面，按最长边 ≤360px 缩放成 dataURL。
// 只接受概览页帧；视图已销毁 / 崩溃 / 后台被丢弃的标签返回空，不让单页拖垮整页。
d.ipcMain.handle('tab-overview-capture', async (event, payload = {}) => {
  if (!d.isTabOverviewFrameSender(event)) return { ok: false, error: 'denied' };
  const id = payload && payload.id != null ? String(payload.id) : '';
  const index = d.tabs.findIndex(t => t && String(t.id) === id);
  if (index < 0) return { ok: false, error: 'not-found' };
  const tab = d.tabs[index];
  const wc = tab && tab.view && tab.view.webContents;
  if (!wc || wc.isDestroyed() || tab.crashed || tab.discarded) {
    return { ok: false, error: 'unavailable' };
  }
  try {
    const image = await wc.capturePage();
    if (image.isEmpty()) return { ok: false, error: 'empty' };
    const size = image.getSize();
    const longest = Math.max(size.width, size.height) || 1;
    let scaled = image;
    if (longest > 360) {
      const factor = 360 / longest;
      scaled = image.resize({
        width: Math.max(1, Math.round(size.width * factor)),
        height: Math.max(1, Math.round(size.height * factor)),
      });
    }
    const dataUrl = scaled.toDataURL();
    if (typeof dataUrl !== 'string' || dataUrl.length > 600000) {
      return { ok: false, error: 'too-large' };
    }
    return { ok: true, dataUrl };
  } catch {
    return { ok: false, error: 'capture-failed' };
  }
});
}

module.exports = { bindDeps, registerFindIpc, registerTabOverviewIpc };
