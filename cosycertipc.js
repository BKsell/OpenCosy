'use strict';

const { registerCertificateBookmarkIpc } = require('./cosycertbookmarkipc');

let d = {};

function bindDeps(x) {
  d = x;
}

function registerCertificateIpc() {
d.ipcMain.handle('history-snapshot', (event) => {
  if (!d.isHistoryFrameSender(event)) return { ok: false, error: 'denied', items: [] };
  const items = d.history.slice(0, d.MAX_HISTORY_ENTRIES).map(item => ({
    url: typeof item.url === 'string' ? item.url.slice(0, 8192) : '',
    title: typeof item.title === 'string' ? item.title.slice(0, 300) : '',
    timestamp: typeof item.timestamp === 'number' && Number.isFinite(item.timestamp) ? item.timestamp : 0,
  }));
  return { ok: true, items };
});

// 历史页删除单条：按 url + timestamp 精确匹配删除（同一 URL 可能有多条时间戳）。
// 匹配不到静默成功；删除后落盘。
d.ipcMain.handle('history-delete-entry', (event, payload = {}) => {
  if (!d.isHistoryFrameSender(event)) return { ok: false, error: 'denied' };
  const url = typeof payload.url === 'string' ? payload.url : '';
  const timestamp = typeof payload.timestamp === 'number' ? payload.timestamp : NaN;
  const before = d.history.length;
  d.history = d.history.filter(item =>
    !(String(item.url || '') === url && item.timestamp === timestamp));
  if (d.history.length !== before) d.saveHistory();
  return { ok: true, removed: before - d.history.length };
});

// 历史页点击条目：经 isSafeUrl 校验后在当前窗口新开标签。cosy:// 内置地址
// 同样放行（历史页“在新标签打开”允许内部页跳转），其余非法协议一律拒绝。
d.ipcMain.handle('history-open-url', (event, url) =>
  d.openUrlFromInternalFrame(d.isHistoryFrameSender(event), url));

// 历史页清空：仅受信帧可触发，与面板“清除历史”共用 saveHistory 落盘。
d.ipcMain.handle('history-clear-all', (event) => {
  if (!d.isHistoryFrameSender(event)) return { ok: false, error: 'denied' };
  d.history = [];
  d.saveHistory();
  return { ok: true };
});

// 历史页批量删除：urls 数组（每项 {url,timestamp}）逐条精确匹配。
// 条数上限防滥用；删除后落盘。
d.ipcMain.handle('history-delete-entries', (event, payload = {}) => {
  if (!d.isHistoryFrameSender(event)) return { ok: false, error: 'denied' };
  const urls = Array.isArray(payload.urls) ? payload.urls : [];
  if (urls.length > 5000) return { ok: false, error: 'too-many' };
  const targets = [];
  for (const it of urls) {
    if (!it || typeof it !== 'object') continue;
    const url = typeof it.url === 'string' ? it.url.slice(0, 8192) : '';
    const timestamp = typeof it.timestamp === 'number' ? it.timestamp : NaN;
    if (!url || !Number.isFinite(timestamp)) continue;
    targets.push({ url, timestamp });
  }
  if (targets.length === 0) return { ok: true, removed: 0 };
  const before = d.history.length;
  d.history = d.history.filter(item => {
    for (const t of targets) {
      if (String(item.url || '') === t.url && item.timestamp === t.timestamp) return false;
    }
    return true;
  });
  if (d.history.length !== before) d.saveHistory();
  return { ok: true, removed: before - d.history.length };
});

// 历史页导出 JSON：弹保存框，写 UTF-8 文件。内容由渲染层传入的纯文本
// （已本地生成），本端仅做类型与长度收口，防止大 payload 撑爆内存。
d.ipcMain.handle('history-export-json', async (event, payload = {}) => {
  if (!d.isHistoryFrameSender(event)) return { ok: false, error: 'denied' };
  try {
    const name = typeof payload.name === 'string' ? payload.name.slice(0, 128).replace(/[^\w.-]/g, '') : 'opencosy-history.json';
    const text = typeof payload.text === 'string' ? payload.text : '';
    if (text.length > 64 * 1024 * 1024) return { ok: false, error: 'too-large' };
    const result = await d.dialog.showSaveDialog(d.mainWindow, {
      title: '导出历史记录',
      defaultPath: name,
      filters: [{ name: 'JSON 文件', extensions: ['json'] }, { name: '所有文件', extensions: ['*'] }],
    });
    if (result.canceled || !result.filePath) return { ok: true, canceled: true };
    d.fsSync.writeFileSync(result.filePath, text, 'utf-8');
    return { ok: true, path: result.filePath, bytes: Buffer.byteLength(text, 'utf-8') };
  } catch (e) {
    console.error('导出历史失败:', e);
    return { ok: false, error: e.message };
  }
});

// 书签管理器快照：返回全量书签（拷贝防外部篡改，标题/URL 长度收口）。
  registerCertificateBookmarkIpc(d);
}

module.exports = { bindDeps, registerCertificateIpc };
