'use strict';

function registerBookmarks(d) {
d.ipcMain.handle('get-bookmarks', (event) => {
  if (!d.isMainSender(event)) return { success: false, bookmarks: [] };
  return { success: true, bookmarks: d.bookmarksks };
});

// 导出书签：format=json 导 OpenCosy 自有 JSON，html 导 Netscape 格式
// （可直接被 Chrome / Edge / Firefox 导入）。
d.ipcMain.handle('export-bookmarks', async (event, format) => {
  if (!d.isMainSender(event)) return { success: false, error: '无权操作' };
  try {
    const useHTML = format === 'html';
    const stamp = new Date().toISOString().slice(0, 10);
    const result = await d.dialog.showSaveDialog(d.mainWindow, {
      title: '导出书签',
      defaultPath: useHTML ? `opencosy-bookmarks-${stamp}.html` : `opencosy-bookmarks-${stamp}.json`,
      filters: useHTML
        ? [{ name: 'Netscape 书签 HTML', extensions: ['html'] }, { name: '所有文件', extensions: ['*'] }]
        : [{ name: 'JSON 书签文件', extensions: ['json'] }, { name: '所有文件', extensions: ['*'] }],
    });
    if (result.canceled || !result.filePath) return { success: false, canceled: true };
    const content = useHTML ? d.bookmarkIO.buildExportHTML(d.bookmarks) : d.bookmarkIO.buildExportJSON(d.bookmarks);
    d.fsSync.writeFileSync(result.filePath, content, 'utf-8');
    return { success: true, count: d.bookmarks.length, format: useHTML ? 'html' : 'json' };
  } catch (e) {
    console.error('导出书签失败:', e);
    return { success: false, error: e.message };
  }
});

// 导入书签：弹原生选择框，按内容自动识别 JSON / Netscape HTML，
// 严格校验后合并去重落盘。整个解析发生在主进程，渲染层只拿到统计结果。
d.ipcMain.handle('import-bookmarks', async (event) => {
  if (!d.isMainSender(event)) return { success: false, error: '无权操作' };
  try {
    const result = await d.dialog.showOpenDialog(d.mainWindow, {
      title: '导入书签',
      properties: ['openFile'],
      filters: [
        { name: '书签文件', extensions: ['html', 'htm', 'json'] },
        { name: '所有文件', extensions: ['*'] },
      ],
    });
    if (result.canceled || !result.filePaths || result.filePaths.length === 0) {
      return { success: false, canceled: true };
    }
    const filePath = result.filePaths[0];
    const stat = d.fsSync.lstatSync(filePath);
    if (!stat.isFile()) {
      return { success: false, error: '书签文件不是普通文件' };
    }
    if (stat.size > d.bookmarkIO.MAX_IMPORT_FILE_BYTES) {
      return { success: false, error: '书签文件过大（上限 8MiB）' };
    }
    const buffer = d.fsSync.readFileSync(filePath);
    const { format: detectedFormat, bookmarks: incoming } = d.bookmarkIO.parseBookmarkFile(buffer);
    const before = d.bookmarks.length;
    const { merged, added } = d.bookmarkIO.mergeBookmarks(d.bookmarks, incoming);
    if (added === 0) {
      return { success: true, added: 0, total: before, format: detectedFormat, duplicated: incoming.length };
    }
    d.bookmarks = merged;
    d.saveBookmarks();
    d.sendToRenderer('bookmarks-updated', d.bookmarks);
    return { success: true, added, total: d.bookmarks.length, format: detectedFormat };
  } catch (e) {
    console.error('导入书签失败:', e);
    return { success: false, error: e.message };
  }
});

d.ipcMain.handle('get-history', (event) => {
  if (!d.isMainSender(event)) return { success: false, history: [] };
  return { success: true, history: d.history.slice(0, 100) };
});

d.ipcMain.handle('clear-history', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  d.history = [];
  d.saveHistory();
  return { success: true };
});
}

module.exports = { registerBookmarks };
