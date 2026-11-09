'use strict';

function registerCertificateBookmarkIpc(d) {
d.ipcMain.handle('bookmarks-snapshot', (event) => {
  if (!d.isBookmarksFrameSender(event)) return { ok: false, error: 'denied', items: [] };
  const items = d.bookmarks.map(d.sanitizeBookmarkLike);
  return { ok: true, items };
});

// 书签管理器打开：经 isSafeUrl 校验（含 cosy:// 内部页），新标签打开。
d.ipcMain.handle('bookmarks-open-url', (event, url) =>
  d.openUrlFromInternalFrame(d.isBookmarksFrameSender(event), url));

// 书签管理器删除：按 url 精确匹配，删除后落盘并广播（书签栏同步）。
d.ipcMain.handle('bookmarks-remove', (event, payload = {}) => {
  if (!d.isBookmarksFrameSender(event)) return { ok: false, error: 'denied' };
  const url = typeof payload.url === 'string' ? payload.url : '';
  const before = d.bookmarks.length;
  d.bookmarks = d.bookmarks.filter(b => !(String(b.url || '') === url));
  if (d.bookmarks.length !== before) {
    d.saveBookmarks();
    d.sendToRenderer('bookmarks-updated', d.bookmarks);
  }
  return { ok: true, removed: before - d.bookmarks.length };
});

// 书签管理器重命名：标题经 300 字收口 + 控制字符清洗，防注入脏文本。
d.ipcMain.handle('bookmarks-rename', (event, payload = {}) => {
  if (!d.isBookmarksFrameSender(event)) return { ok: false, error: 'denied' };
  const url = typeof payload.url === 'string' ? payload.url : '';
  let title = typeof payload.title === 'string' ? payload.title : '';
  title = title.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 300).trim();
  if (!title) return { ok: false, error: 'bad-title' };
  const b = d.bookmarks.find(x => String(x.url || '') === url);
  if (!b) return { ok: false, error: 'not-found' };
  b.title = title;
  d.saveBookmarks();
  d.sendToRenderer('bookmarks-updated', d.bookmarks);
  return { ok: true, title };
});

// 稍后读快照：返回全量条目（拷贝防外部篡改，标题/URL 长度收口，与书签同款净化）。
d.ipcMain.handle('readinglist-snapshot', (event) => {
  if (!d.isReadingListFrameSender(event)) return { ok: false, error: 'denied', items: [] };
  const items = d.readingList.map(d.sanitizeBookmarkLike);
  return { ok: true, items };
});
}

module.exports = { registerCertificateBookmarkIpc };
