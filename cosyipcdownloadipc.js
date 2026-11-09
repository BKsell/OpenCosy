'use strict';

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
d.ipcMain.handle('get-download-shelf', () => d.shelfSnapshot());

// copy-text：受控剪贴板写入（下载项右键“复制链接/复制文件名”用）。
// 只接受字符串、长度上限 4096，避免恶意渲染层借 IPC 写入超长文本 / 二进制垃圾；
// 文本本身由调用方（renderer 右键菜单）提供，这里仅做类型与长度收口。
d.ipcMain.on('copy-text', (event, text) => {
  if (!d.isMainSender(event)) return;
  if (typeof text !== 'string' || text.length === 0 || text.length > 4096) return;
  d.clipboard.writeText(text);
});

d.ipcMain.on('shelf-show-all', (event) => {
  if (!d.isMainSender(event)) return;
  d.createNewTab('cosy://downloadlist');
});

d.ipcMain.on('pause-download', (event, id) => {
  if (!d.isMainSender(event)) return;
  const download = d.downloads.find(d => d.id === id);
  if (download && download.item && download.isItemValid) {
    try {
      if (download.item.getState() === 'progressing') {
        download.item.pause();
        download.status = 'paused';
        d.sendToRenderer('download-status-changed', { id: download.id, status: 'paused' });
        d.sendShelf();
      }
    } catch (e) {
      console.error('暂停下载失败:', e);
      download.isItemValid = false; download.status = 'error';
      d.sendToRenderer('download-status-changed', { id: download.id, status: 'error' });
    }
  }
});

d.ipcMain.on('resume-download', (event, id) => {
  if (!d.isMainSender(event)) return;
  const download = d.downloads.find(d => d.id === id);
  if (download && download.item && download.isItemValid) {
    try {
      const state = download.item.getState();
      if (state === 'interrupted' || state === 'cancelled') {
        download.item.resume();
        download.status = 'downloading';
        d.sendToRenderer('download-status-changed', { id: download.id, status: 'downloading' });
        d.sendShelf();
      }
    } catch (e) {
      console.error('恢复下载失败:', e);
      download.isItemValid = false; download.status = 'error';
      d.sendToRenderer('download-status-changed', { id: download.id, status: 'downloading' });
    }
  }
});

d.ipcMain.on('cancel-download', (event, id) => {
  if (!d.isMainSender(event)) return;
  const download = d.downloads.find(d => d.id === id);
  if (download && download.item && download.isItemValid) {
    try {
      const state = download.item.getState();
      if (state === 'progressing' || state === 'interrupted') download.item.cancel();
      download.isItemValid = false; download.status = 'error';
      d.sendToRenderer('download-status-changed', { id: download.id, status: 'error' });
    } catch (e) {
      console.error('取消下载失败:', e);
      download.isItemValid = false; download.status = 'error';
      d.sendToRenderer('download-status-changed', { id: download.id, status: 'error' });
    }
  }
});

d.ipcMain.on('retry-download', (event, data) => {
  if (!d.isMainSender(event)) return;
  const url = data && typeof data === 'object' ? data.url : null;
  if (typeof url === 'string' && url.length > 0 && d.isSafeUrl(url)) d.session.defaultSession.downloadURL(url);
});

d.ipcMain.on('remove-download', (event, id) => {
  if (!d.isMainSender(event)) return;
  const index = d.downloads.findIndex(d => d.id === id);
  if (index !== -1) {
    d.downloads.splice(index, 1);
    d.sendToRenderer('download-removed', { id });
    d.sendShelf();
  }
});

// performDownloadOpen 是“打开已下载文件”的唯一执行出口：下载列表 IPC 与系统
// 通知点击都走这里。判定交给 dloadopen 内核（文件名伪装、来源、容器类型），
// UI（确认框）与系统调用留在这里，避免通知点击绕过来源确认与路径消毒。

d.ipcMain.on('open-file', (event, filePath) => {
  if (!d.isMainSender(event)) return;
  d.performDownloadOpen(d.path.resolve(filePath));
});

d.ipcMain.on('open-folder', (event, filePath) => {
  if (!d.isMainSender(event)) return;
  const resolved = d.path.resolve(filePath);
  if (!d.isInSafeDirs(resolved) || !d.fsSync.existsSync(resolved)) return;
  const revealReview = d.shellGuard.reviewLocalLaunchPath(resolved, true);
  if (!revealReview.ok) {
    d.recordSecurityEvent('download-blocked', 'warn',
      `定位本地文件被路径消毒拦截（${d.shellGuard.describeReason(revealReview.reason)}）`, '');
    return;
  }
  d.shell.showItemInFolder(resolved);
});

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
