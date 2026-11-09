'use strict';

function registerTabSurfaceAuxIpc(d) {
d.ipcMain.handle('pages-snapshot', (event) => {
  if (!d.isPagesFrameSender(event)) return { ok: false, error: 'denied', pages: [] };
  const pages = Object.keys(d.INTERNAL_PAGES).map(name => ({
    name,
    title: d.INTERNAL_PAGES[name].title,
    desc: d.INTERNAL_PAGES[name].desc,
  }));
  return { ok: true, pages };
});

// 内部页导航打开：只接受登记表内存在的页面名，白名单外一律拒绝（防止把任意
// 字符串拼进 cosy:// 后跳转到未注册地址）。新标签打开。
d.ipcMain.handle('pages-open', (event, payload = {}) => {
  if (!d.isPagesFrameSender(event)) return { ok: false, error: 'denied' };
  const name = typeof payload.name === 'string' ? payload.name : '';
  if (!d.INTERNAL_PAGES[name]) return { ok: false, error: 'unknown-page' };
  const tab = d.createNewTab('cosy://' + name);
  return { ok: true, id: tab.id, name };
});

d.ipcMain.handle('get-https-only', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  return { success: true, enabled: d.httpsOnlyEnabled };
});

// HTTPS-Only 站点例外的查询与管理。来源校验交给 ipcGuard（仅受信 file/cosy 帧，
// 远程网页在主进程边界即被拒）；主机名一律经内核净化，非法输入返回 ok:false，
// 不接受路径 / 端口 / 控制字符。写操作落盘并向所有受信界面广播变更。
d.ipcMain.handle('list-https-exceptions', () => ({
  enabled: d.httpsOnlyEnabled,
  hosts: d.httpsExceptions.hosts(),
  size: typeof d.httpsExceptions.size === 'function' ? d.httpsExceptions.size() : 0,
  capacity: d.httpsExceptions.capacity || 0,
}));

d.ipcMain.handle('add-https-exception', (event, payload = {}) => {
  const host = d.httpsOnlyCore.normalizeExceptionHost(payload && payload.host);
  if (!host) return { ok: false, error: '主机名无效' };
  d.httpsExceptions.add(host);
  d.persistHttpsExceptions();
  d.sendToRenderer('https-exceptions-updated', { hosts: d.httpsExceptions.hosts() });
  return { ok: true, host };
});

d.ipcMain.handle('remove-https-exception', (event, payload = {}) => {
  const host = d.httpsOnlyCore.normalizeExceptionHost(payload && payload.host);
  if (!host) return { ok: false, error: '主机名无效' };
  const removed = d.httpsExceptions.remove(host);
  if (removed) {
    d.persistHttpsExceptions();
    d.sendToRenderer('https-exceptions-updated', { hosts: d.httpsExceptions.hosts() });
  }
  return { ok: true, removed };
});

d.ipcMain.handle('clear-https-exceptions', () => {
  d.httpsExceptions.clear();
  d.persistHttpsExceptions();
  d.sendToRenderer('https-exceptions-updated', { hosts: d.httpsExceptions.hosts() });
  return { ok: true };
});

d.ipcMain.handle('get-network-status', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  return { success: true, online: d.net.isOnline() };
});

// 阅读页读取本次抽取结果（分级 COSY_ONLY，仅 cosy://reader 帧可调）。文章保留到
// 阅读标签关闭或下一次抽取，便于页面内切换字号 / 暗色后重建时重复取用。
d.ipcMain.handle('get-reader-article', () => {
  const article = d.readerArticle;
  return article || { ok: false, contentNodes: [] };
});

d.ipcMain.handle('get-trackers', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  return { success: true, enabled: d.blockTrackers, count: d.blockedTrackerCount, top: d.topBlockedHosts() };
});

d.ipcMain.on('reset-trackers', (event) => {
  if (!d.isMainSender(event)) return;
  d.blockedTrackerCount = 0;
  d.blockedTrackerByHost.clear();
  d.sendToRenderer('trackers-blocked', { count: 0, host: '', top: [] });
});
}

module.exports = { registerTabSurfaceAuxIpc };
