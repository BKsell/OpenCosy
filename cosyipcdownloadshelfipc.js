'use strict';

function registerDownloadShelfIpc(d) {
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
}

module.exports = { registerDownloadShelfIpc };
