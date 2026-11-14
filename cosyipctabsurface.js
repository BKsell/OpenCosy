'use strict';

const { registerTabSurfaceAuxIpc } = require('./cosyipctabsurface_aux');

function registerTabSurfaces(d) {
d.ipcMain.handle('readinglist-add', (event, payload = {}) => {
  if (!d.isReadingListFrameSender(event) && !d.isMainSender(event)) return { ok: false, error: 'denied' };
  const url = typeof payload.url === 'string' ? payload.url : '';
  return d.addToReadingList(url, payload.title);
});

// 稍后读打开：经 isSafeUrl 校验（含 cosy:// 内部页），新标签打开。
d.ipcMain.handle('readinglist-open-url', (event, url) =>
  d.openUrlFromInternalFrame(d.isReadingListFrameSender(event), url));

// 稍后读删除：按 url 精确匹配，删除后落盘。
d.ipcMain.handle('readinglist-remove', (event, payload = {}) => {
  if (!d.isReadingListFrameSender(event)) return { ok: false, error: 'denied' };
  const url = typeof payload.url === 'string' ? payload.url : '';
  const before = d.readingList.length;
  d.readingList = d.readingList.filter(b => !(String(b.url || '') === url));
  if (d.readingList.length !== before) d.saveReadingList();
  return { ok: true, removed: before - d.readingList.length };
});

// 稍后读清空：整表清空并落盘。
d.ipcMain.handle('readinglist-clear', (event) => {
  if (!d.isReadingListFrameSender(event)) return { ok: false, error: 'denied' };
  const before = d.readingList.length;
  d.readingList = [];
  if (before > 0) d.saveReadingList();
  return { ok: true, removed: before };
});

// 关于页快照：版本 / 运行时 / 安全开关 / 跨主机连接台账汇总。
// 只放行 cosy://about 帧与主窗口外壳；不做任何网络请求，纯本地信息。
d.ipcMain.handle('about-snapshot', (event) => {
  if (!d.isAboutFrameSender(event)) return { ok: false, error: 'denied' };
  const stats = d.getRequestLogStats();
  const secEvents = d.listSecurityEvents('', 500);
  const secStats = { total: 0, critical: 0, warn: 0, info: 0, latest: [] };
  for (const e of secEvents) {
    secStats.total++;
    if (e.severity === 'critical') secStats.critical++;
    else if (e.severity === 'warn') secStats.warn++;
    else secStats.info++;
  }
  secStats.latest = secEvents.slice(0, 5).map(e => ({
    time: e.time, type: String(e.type || ''), severity: String(e.severity || 'info'),
    detail: String(e.detail || '').slice(0, 160),
  }));
  return {
    ok: true,
    info: {
      appName: 'OpenCosy',
      appVersion: typeof d.app.getVersion === 'function' ? d.app.getVersion() : '',
      userDataPath: d.app.getPath('userData'),
      internalPages: Object.keys(pageMap).length,
      electronVersion: process.versions.electron || '',
      chromiumVersion: process.versions.chrome || '',
      nodeVersion: process.versions.node || '',
      v8Version: process.versions.v8 || '',
      platform: process.platform || '',
      arch: process.arch || '',
      httpsOnly: d.httpsOnlyEnabled,
      httpsOnlyBlockInsecure: !!d.httpsOnlyEnabled,
      dnt: true,
      disableWebRTC: d.webrtcMode !== 'legacy',
      webrtcMode: d.webrtcModede,
      httpsExceptions: typeof d.httpsExceptions.size === 'function' ? d.httpsExceptions.size() : 0,
      tabCount: Array.isArray(d.tabs) ? d.tabs.length : 0,
      bookmarkCount: Array.isArray(d.bookmarks) ? d.bookmarks.length : 0,
      stats: {
        hosts: Number(stats.hosts) || 0,
        requests: Number(stats.requests) || 0,
        blocked: Number(stats.blocked) || 0,
        backgroundHosts: Number(stats.backgroundHosts) || 0,
        insecureHosts: Number(stats.insecureHosts) || 0,
      },
      security: secStats,
    },
  };
});

// 关于页导出诊断 JSON：渲染层已本地生成纯文本，本端仅收口类型与长度，
// 弹保存框写盘。仅受信帧可触发。
d.ipcMain.handle('about-export-diagnostics', async (event, payload = {}) => {
  if (!d.isAboutFrameSender(event)) return { ok: false, error: 'denied' };
  try {
    const text = typeof payload.text === 'string' ? payload.text : '';
    if (text.length > 16 * 1024 * 1024) return { ok: false, error: 'too-large' };
    const stamp = new Date().toISOString().slice(0, 10);
    const result = await d.dialog.showSaveDialog(d.mainWindow, {
      title: '导出诊断信息',
      defaultPath: `opencosy-diagnostics-${stamp}.json`,
      filters: [{ name: 'JSON 文件', extensions: ['json'] }, { name: '所有文件', extensions: ['*'] }],
    });
    if (result.canceled || !result.filePath) return { ok: true, canceled: true };
    d.fsSync.writeFileSync(result.filePath, text, 'utf-8');
    return { ok: true, path: result.filePath };
  } catch (e) {
    console.error('导出诊断失败:', e);
    return { ok: false, error: e.message };
  }
});

// 快捷键速查页快照：导出规则表（动作 id + 键位 + 修饰键），供 cosy://shortcuts// 渲染。只放行内置帧；规则键值全部标量化，避免把内部对象引用暴露给页面。
d.ipcMain.handle('shortcuts-snapshot', (event) => {
  if (!d.isShortcutsFrameSender(event)) return { ok: false, error: 'denied', rules: [] };
  const rules = d.shortcutKeys.SHORTCUT_RULES.map(r => ({
    action: String(r.action || ''),
    key: String(r.key || ''),
    ctrl: r.ctrl === true ? 1 : r.ctrl === false ? 0 : null,
    shift: r.shift === true ? 1 : r.shift === false ? 0 : null,
    alt: r.alt === true ? 1 : r.alt === false ? 0 : null,
  }));
  return { ok: true, rules };
});

// 内部页导航快照：返回全部已登记内部页（名称 / 标题 / 说明），供 cosy://pages
// 渲染。只放行内置帧；标题说明为静态文案，名称经白名单校验后才可用于打开。
  registerTabSurfaceAuxIpc(d);
}

module.exports = { registerTabSurfaces };
