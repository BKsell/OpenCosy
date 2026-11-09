'use strict';

let d = {};

function bindDeps(x) {
  d = x;
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

module.exports = { bindDeps, registerTabOverviewIpc };
