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

const cosyipcoverview = require('./cosyipcoverview');

function bindDepsAll(x) {
  d = x;
  cosyipcoverview.bindDeps(x);
}

module.exports = Object.assign({ bindDeps: bindDepsAll }, cosyipcoverview, { bindDeps, registerFindIpc });
