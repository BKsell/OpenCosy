'use strict';

const pagesave = require('./pagesave');
const { registerDownloadShelfIpc } = require('./cosyipcdownloadshelfipc_core');

function registerDownloadIpc(d) {
d.ipcMain.on('get-download-info', (event) => {
  // 只允许主界面查询当前下载信息，防止任何被攻陷的 webContents
  // 通过该通道读取本地保存路径等环境信息。
  if (!d.isMainSender(event)) return;
  if (d.currentDownloadInfo) {
    event.reply('download-info', {
      url: d.currentDownloadInfo.url,
      filename: d.currentDownloadInfo.filename,
      totalBytes: d.currentDownloadInfo.totalBytes || 0
    });
  }
});

d.ipcMain.on('start-download', (event, data) => {
  if (!d.isMainSender(event)) return;
  const payload = data && typeof data === 'object' ? data : {};
  if (d.currentDownloadInfo) {
    try {
      const fallbackName = d.sanitizeDownloadFilename(d.currentDownloadInfo.filename);
      let savePath = d.path.join(d.app.getPath('downloads'), fallbackName);
      if (payload.savePath) {
        const requestedPath = d.path.resolve(String(payload.savePath));
        const safeRoot = d.getSafeDirs().find((dir) => d.isPathInDir(requestedPath, dir));
        const targetCheck = safeRoot
          ? d.downloadSaveTarget.auditSaveTargetReal(safeRoot, requestedPath, d.path.basename(requestedPath))
          : null;
        if (targetCheck && targetCheck.ok) savePath = targetCheck.path;
      }
      if (d.currentDownloadInfo.item && d.currentDownloadInfo.isItemValid) {
        d.currentDownloadInfo.item.setSavePath(savePath);
        d.currentDownloadInfo.savePath = savePath;
        d.currentDownloadInfo.status = 'downloading';
      } else {
        d.currentDownloadInfo.savePath = savePath;
        d.currentDownloadInfo.status = 'pending';
        d.currentDownloadInfo.item = null;
        d.currentDownloadInfo.isItemValid = false;
        d.session.defaultSession.downloadURL(d.currentDownloadInfo.url);
      }
      d.sendToRenderer('download-started', { id: d.currentDownloadInfo.id });
    } catch (e) {
      console.error('启动下载失败:', e);
      d.currentDownloadInfo.isItemValid = false;
      d.currentDownloadInfo.status = 'error';
    }
  }
});

d.ipcMain.on('show-save-dialog', (event, data) => {
  if (!d.isMainSender(event)) return;
  const payload = data && typeof data === 'object' ? data : {};
  d.dialog.showSaveDialog(d.mainWindow, {
    defaultPath: d.path.join(d.app.getPath('downloads'), d.sanitizeDownloadFilename(payload.defaultName || 'download')),
    filters: [{ name: 'All Files', extensions: ['*'] }]
  }).then(result => {
    if (!result.canceled && result.filePath) {
      if (d.currentDownloadInfo && d.currentDownloadInfo.item && d.currentDownloadInfo.isItemValid) {
        try {
          const state = d.currentDownloadInfo.item.getState();
          if (state === 'progressing' || state === 'interrupted') d.currentDownloadInfo.item.cancel();
          d.currentDownloadInfo.isItemValid = false;
          d.currentDownloadInfo.status = 'error';
        } catch (e) { console.error('取消下载以另存为失败:', e); }
      }
      if (d.currentDownloadInfo) {
        const chosenVerdict = d.downloadSaveTarget.auditSaveName(d.path.basename(result.filePath));
        if (chosenVerdict !== d.downloadSaveTarget.REASON.OK) {
          d.sendToRenderer('show-toast',
            `另存为文件名非法，已取消：${d.downloadSaveTarget.describeSaveTargetReject(chosenVerdict)}`);
          return;
        }
        d.currentDownloadInfo.savePath = result.filePath;
        d.currentDownloadInfo.status = 'pending';
        d.currentDownloadInfo.item = null;
        d.currentDownloadInfo.isItemValid = false;
      }
      if (payload.url && d.isSafeUrl(payload.url)) d.session.defaultSession.downloadURL(payload.url);
      event.reply('download-started', { id: d.currentDownloadInfo ? d.currentDownloadInfo.id : null });
    }
  });
});

d.ipcMain.on('get-downloads', (event) => {
  if (!d.isMainSender(event)) return;
  const serializableDownloads = d.downloads.map(d => ({
    id: d.id, url: d.url, filename: d.filename, totalBytes: d.totalBytes,
    receivedBytes: d.receivedBytes, progress: d.progress, speed: d.speed,
    status: d.status, startTime: d.startTime, savePath: d.savePath
  }));
  event.reply('downloads-list', serializableDownloads);
});

// ===== 底部下载栏 IPC =====
  registerDownloadShelfIpc(d);

// open-external-url renderer 统一入口：点 mailto:/tel: 走这里，
// 主进程做协议校验 + 按站点记忆 + 原生确认，再调 shell.openExternal。
d.ipcMain.handle('open-external-url', async (event, url) => {
  if (!d.isMainSender(event)) return { ok: false, reason: 'unauthorized' };
  const origin = d.urlResolve.safeOrigin(event.sender.getURL());
  return await d.confirmAndOpenExternal(String(url || ''), origin);
});

// 供设置页读取 / 撤销"站点 -> 外部协议"的记忆决定。
d.ipcMain.handle('get-protocol-decisions', (event) => {
  if (!d.isMainSender(event)) return { ok: false, reason: 'unauthorized' };
  return { ok: true, items: d.listProtocolDecisions() };
});

d.ipcMain.handle('clear-protocol-decision', (event, data) => {
  if (!d.isMainSender(event)) return { ok: false, reason: 'unauthorized' };
  const origin = data && typeof data.origin === 'string' ? data.origin : '';
  const scheme = data && typeof data.scheme === 'string' ? data.scheme : '';
  return d.forgetProtocolDecision(origin, scheme);
});

d.ipcMain.handle('save-current-page', async (event, data) => {
  if (!d.isMainSender(event)) return { ok: false, reason: 'unauthorized' };
  const tab = d.tabs && d.tabs[d.currentTabIndex];
  const wc = tab && tab.view && tab.view.webContents;
  if (!wc || (typeof wc.isDestroyed === 'function' && wc.isDestroyed())) {
    return { ok: false, reason: 'no-tab' };
  }
  const requested = data && typeof data.path === 'string' ? data.path : '';
  let target = '';
  if (requested) {
    const resolved = d.path.resolve(requested);
    const safeRoot = d.getSafeDirs().find((dir) => d.isPathInDir(resolved, dir));
    if (!safeRoot) return { ok: false, reason: 'outside-safe-dirs' };
    const checked = d.downloadSaveTarget.auditSaveTargetReal(safeRoot, resolved, d.path.basename(resolved));
    if (!checked || !checked.ok) return { ok: false, reason: 'unsafe-target' };
    target = pagesave.normalizeSavePath(checked.path, ['.html', '.htm'], '.html');
  } else {
    target = d.path.join(d.app.getPath('downloads'), pagesave.buildSaveName(wc.getTitle(), '.html'));
  }
  if (!target) return { ok: false, reason: 'bad-path' };
  try {
    await wc.savePage(target, 'HTMLComplete');
    return { ok: true, path: target };
  } catch (err) {
    return { ok: false, reason: 'save-failed', message: err && err.message ? err.message : 'unknown' };
  }
});

d.ipcMain.on('clear-downloads', (event) => {
  if (!d.isMainSender(event)) return;
  d.downloads = [];
  d.currentDownloadInfo = null;
  d.sendToRenderer('downloads-cleared');
  setTimeout(() => {
    d.sendToRenderer('clear-downloads-success', '下载列表已成功清空');
  }, 100);
});
}

module.exports = { registerDownloadIpc };
