let d = {};
function bindDeps(x) {
  d = x;
}
function registerNetworkGuards() {
d.ipcMain.handle('submit-network-auth', (event, payload = {}) => {
  if (!d.isMainSender(event)) return { ok: false, error: 'denied' };
  const challenge = d.pendingAuthChallenges.get(payload.nonce);
  if (!challenge || challenge.kind !== 'login') return { ok: false, error: '挑战已过期或无效' };
  const clean = d.netAuthGuard.sanitizeAuthSubmit({ username: payload.username, password: payload.password });
  if (!clean.ok) return { ok: false, error: '账号或口令不合法' };
  clearTimeout(challenge.timer);
  d.pendingAuthChallenges.delete(payload.nonce);
  try { challenge.callback(clean.username, clean.password); } catch {}
  d.authLimiter.reset(challenge.key);
  d.authStats.recordSuccess();
  return { ok: true };
});

d.ipcMain.handle('cancel-network-auth', (event, payload = {}) => {
  if (!d.isMainSender(event)) return { ok: false, error: 'denied' };
  return { ok: d.rejectAuthChallenge(payload.nonce) };
});

// 渲染层选择客户端证书；remember=true 时把该主机->指纹记入台账。
d.ipcMain.handle('choose-client-cert', (event, payload = {}) => {
  if (!d.isMainSender(event)) return { ok: false, error: 'denied' };
  const challenge = d.pendingAuthChallenges.get(payload.nonce);
  if (!challenge || challenge.kind !== 'cert') return { ok: false, error: '挑战已过期或无效' };
  const idx = Number(payload.index);
  const list = Array.isArray(challenge.certificateList) ? challenge.certificateList : [];
  if (!Number.isInteger(idx) || idx < 0 || idx >= list.length) {
    return { ok: false, error: '证书序号无效' };
  }
  clearTimeout(challenge.timer);
  d.pendingAuthChallenges.delete(payload.nonce);
  try { challenge.callback(list[idx]); } catch {}
  if (payload.remember === true && challenge.hostname) {
    if (d.clientCertStore.remember(challenge.hostname, list[idx], Date.now())) d.persistClientCertChoices();
  }
  d.sendToRenderer('client-cert-choices-updated', d.getClientCertChoiceStats());
  return { ok: true };
});

d.ipcMain.handle('cancel-client-cert', (event, payload = {}) => {
  if (!d.isMainSender(event)) return { ok: false, error: 'denied' };
  const challenge = d.pendingAuthChallenges.get(payload.nonce);
  if (!challenge || challenge.kind !== 'cert') return { ok: false, error: '挑战已过期或无效' };
  clearTimeout(challenge.timer);
  d.pendingAuthChallenges.delete(payload.nonce);
  try { challenge.callback(); } catch {}
  return { ok: true };
});

d.ipcMain.handle('list-remembered-certs', (event, payload = {}) => {
  if (!d.isMainSender(event)) return { ok: false, error: 'denied' };
  d.loadClientCertChoices();
  const limit = Math.min(Number(payload.limit) || d.netAuthGuard.MAX_REMEMBERED_CERT_HOSTS, d.netAuthGuard.MAX_REMEMBERED_CERT_HOSTS);
  return { ok: true, entries: d.clientCertStore.list().slice(0, limit), stats: d.getClientCertChoiceStats() };
});

d.ipcMain.handle('forget-remembered-cert', (event, payload = {}) => {
  if (!d.isMainSender(event)) return { ok: false, error: 'denied' };
  if (typeof payload.host !== 'string') return { ok: false, error: 'bad-host' };
  d.clientCertStore.forget(payload.host);
  d.persistClientCertChoices();
  d.sendToRenderer('client-cert-choices-updated', d.getClientCertChoiceStats());
  return { ok: true };
});

d.ipcMain.handle('clear-remembered-certs', (event) => {
  if (!d.isMainSender(event)) return { ok: false, error: 'denied' };
  d.clientCertStore.clear();
  d.persistClientCertChoices();
  d.sendToRenderer('client-cert-choices-updated', d.getClientCertChoiceStats());
  return { ok: true };
});

d.ipcMain.handle('get-auth-stats', (event) => {
  if (!d.isMainSender(event)) return { ok: false, error: 'denied' };
  return { ok: true, stats: d.authStats.toJSON() };
});

// ===== Cookie 加固台账（cosy://security 面板）=====
d.ipcMain.handle('list-cookie-hardening', (event) => {
  if (!d.isMainSender(event)) return { ok: false, error: 'denied', entries: [] };
  d.loadCookieLedger();
  return { ok: true, entries: d.cookieLedger.list() };
});

d.ipcMain.handle('get-cookie-hardening-stats', (event) => {
  if (!d.isMainSender(event)) return { ok: false, error: 'denied' };
  d.loadCookieLedger();
  return { ok: true, stats: d.cookieLedger.stats() };
});

d.ipcMain.handle('clear-cookie-hardening', (event) => {
  if (!d.isMainSender(event)) return { ok: false, error: 'denied' };
  d.cookieLedger.clear();
  d.persistCookieLedger();
  d.sendToRenderer('cookie-hardening-updated', d.cookieLedger.stats());
  return { ok: true, stats: d.cookieLedger.stats() };
});

// ===== PNA 私有网络访问台账 =====
d.ipcMain.handle('list-pna-blocks', (event) => {
  if (!d.isMainSender(event)) return { ok: false, error: 'denied', entries: [] };
  d.loadPnaLedger();
  const entries = [...d.pnaLedger.values()].sort((a, b) => b.lastTime - a.lastTime);
  return { ok: true, entries };
});

d.ipcMain.handle('get-pna-block-stats', (event) => {
  if (!d.isMainSender(event)) return { ok: false, error: 'denied' };
  d.loadPnaLedger();
  return { ok: true, stats: d.pnaLedgerStats() };
});

d.ipcMain.handle('clear-pna-blocks', (event) => {
  if (!d.isMainSender(event)) return { ok: false, error: 'denied' };
  d.pnaLedger.clear();
  d.persistPnaLedger();
  d.sendToRenderer('pna-blocked-updated', d.pnaLedgerStats());
  return { ok: true, stats: d.pnaLedgerStats() };
});

d.ipcMain.handle('list-fingerprint-entries', (event) => {
  if (!d.isMainSender(event)) return { ok: false, error: 'denied', entries: [] };
  d.loadFpLedger();
  return { ok: true, entries: d.fpLedger.entries() };
});

d.ipcMain.handle('get-fingerprint-stats', (event) => {
  if (!d.isMainSender(event)) return { ok: false, error: 'denied' };
  d.loadFpLedger();
  return { ok: true, stats: d.fpLedger.stats() };
});

d.ipcMain.handle('clear-fingerprint-entries', (event) => {
  if (!d.isMainSender(event)) return { ok: false, error: 'denied' };
  d.fpLedger.clear();
  d.persistFpLedger();
  d.sendToRenderer('fingerprint-blocked-updated', d.fpLedger.stats());
  return { ok: true, stats: d.fpLedger.stats() };
});

d.ipcMain.handle('get-doh-status', (event) => {
  if (!d.isMainSender(event)) return { ok: false, error: 'denied' };
  d.loadDohLedger();
  return {
    ok: true,
    supported: typeof d.session.defaultSession.setHostResolverControls === 'function',
    status: d.dohStatus(),
    providers: d.dohGuard.KNOWN_PROVIDERS,
    forcedFeatures: d.permPolicy.FORCED_DISABLE,
  };
});

d.ipcMain.handle('clear-doh-events', (event) => {
  if (!d.isMainSender(event)) return { ok: false, error: 'denied' };
  d.dohLedger.clear();
  d.persistDohLedger();
  return { ok: true };
});
}
function registerDownloadShelf() {
d.ipcMain.on('save-settings', (event, settings) => {
  if (!d.isMainSender(event)) return;
  // r33：settings 是“整包序列化落盘”通道，先用 inputGuard 做形状与体量裁决：
  // 非普通对象 / 嵌套过深 / 键数过多 / 体量逼近磁盘上限（16MiB）一律拒绝，防止
  // 被攻陷渲染层用深层巨型对象打爆内存与 cosySettings.json。
  const objRes = d.inputGuard.asPlainObject(settings);
  if (!objRes.ok) {
    d.recordSecurityEvent('ipc-input-rejected', 'warn',
      'save-settings 收到非普通对象入参，已拒绝', d.originOfContents(event.sender));
    event.reply('settings-saved', { success: false, error: 'invalid settings payload' });
    return;
  }
  const measure = d.inputGuard.measureObject(settings);
  if (!measure.ok) {
    d.recordSecurityEvent('ipc-input-rejected', 'warn',
      `save-settings 整包体量异常已拒绝（${measure.reason}，keys=${measure.keys}，bytes=${measure.bytes}）`,
      d.originOfContents(event.sender));
    event.reply('settings-saved', { success: false, error: 'settings payload too large' });
    return;
  }
  try {
    const clean = d.sanitizeSettings(settings);
    const settingsPath = d.path.join(d.app.getPath('userData'), 'cosySettings.json');
    // 崩溃安全原子写：避免写一半断电导致设置文件截断、下次启动全部偏好丢失。
    d.ledgerStore.writeJSONStore(settingsPath, clean, { pretty: true });
    // 立即把 darkMode / httpsOnly / memorySaver 应用到运行时
    d.applyDarkMode(clean.darkMode);
    d.httpsOnlyEnabled = clean.httpsOnly !== false;
    d.bookmarkBarVisible = clean.bookmarkBarVisible !== false;
    d.blockTrackers = clean.blockTrackers !== false;
    d.blockThirdPartyCookies = clean.blockThirdPartyCookies !== false;
    d.hardenCookies = clean.hardenCookies !== false;
    d.blockLocalNetworkAccess = clean.blockLocalNetworkAccess !== false;
    d.reduceClientHints = clean.reduceClientHints !== false;
    d.blockAdSignals = clean.blockAdSignals !== false;
    d.blockHyperlinkPing = clean.blockHyperlinkPing !== false;
    d.stripAcceptCh = clean.stripAcceptCh !== false;
    if ('allowPictureInPicture' in clean) d.allowPictureInPicture = !!clean.allowPictureInPicture;
    if ('searchEngine' in clean) d.searchProviderId = d.searchProvider.sanitizeProviderChoice(clean.searchEngine);
    if ('webrtcMode' in clean) d.webrtcMode = d.fpGuard.normalizeWebRtcMode(clean.webrtcMode);
    d.applyWebRtcPolicy();
    if ('dohMode' in clean) d.dohMode = d.dohGuard.normalizeMode(clean.dohMode);
    if ('dohProvider' in clean) d.dohProvider = clean.dohProvider;
    if ('dohCustomUrl' in clean) d.dohCustomUrl = clean.dohCustomUrl;
    d.applySecureDns();
    d.crashRecoveryEnabled = clean.crashRecovery !== false;
    d.stripTrackingParams = clean.stripTrackingParams !== false;
    if ('memorySaver' in clean) d.memorySaverEnabled = !!clean.memorySaver;
    if ('clearOnExit' in clean) d.clearOnExit = !!clean.clearOnExit;
    if ('confirmCloseMultiple' in clean) d.confirmCloseMultiple = !!clean.confirmCloseMultiple;
    if ('spellcheckEnabled' in clean) d.spellcheckEnabled = !!clean.spellcheckEnabled;
    if ('spellcheckLanguages' in clean) d.spellcheckLanguages = d.sanitizeSpellcheckLanguages(clean.spellcheckLanguages);
    if ('downloadMaxBytes' in clean) d.downloadMaxBytes = d.downloadSizeGuard.normalizeLimit(clean.downloadMaxBytes);
    d.applySpellcheckSettings();
    event.reply('settings-saved', { success: true });
  } catch (e) {
    console.error('保存设置失败:', e);
    event.reply('settings-saved', { success: false, error: e.message });
  }
});

d.ipcMain.on('update-theme-color', (event, color) => {
  if (!d.isMainSender(event)) return;
  if (!d.isValidColor(color)) return;
  d.sendToRenderer('update-theme-color', color);
  d.tabs.forEach(tab => {
    if (tab.view?.webContents) tab.view.webContents.send('update-theme-color', color);
  });
});

d.ipcMain.on('get-settings', (event) => {
  if (!d.isMainSender(event)) return;
  try {
    // 复用统一的有界设置读取，坏 / 超大文件回落 {}，不再 existsSync+整读。
    event.reply('settings-loaded', d.readStoredSettings());
  } catch (e) {
    console.error('读取设置失败:', e);
    event.reply('settings-loaded', {});
  }
});

// get-spellcheck-info 返回拼写检查当前状态与平台实际可用的语言列表，
// 设置页据此隐藏当前系统没有词典的语言，避免用户勾了一个永远不生效的选项。
d.ipcMain.handle('get-spellcheck-info', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  let available = [];
  try {
    available = d.session.defaultSession.availableSpellCheckerLanguages || [];
  } catch (e) {
    console.error('读取可用拼写语言失败:', e);
  }
  const availableSet = new Set(available);
  return {
    success: true,
    enabled: d.spellcheckEnabled,
    languages: d.spellcheckLanguages,
    selectable: d.ALLOWED_SPELLCHECK_LANGUAGES.filter(l => availableSet.has(l))
  };
});

d.ipcMain.on('export-config', async (event, content) => {
  if (!d.isMainSender(event)) return;
  try {
    const result = await d.dialog.showSaveDialog(d.mainWindow, {
      title: '导出配置', defaultPath: 'cosy_config.inf',
      filters: [{ name: '配置文件', extensions: ['inf'] }, { name: '所有文件', extensions: ['*'] }]
    });
    if (!result.canceled && result.filePath) {
      d.fsSync.writeFileSync(result.filePath, content, 'utf-8');
      event.reply('export-config-success', '配置文件导出成功！');
    } else {
      event.reply('export-config-canceled', '导出操作已取消');
    }
  } catch (e) {
    console.error('导出配置失败:', e);
    event.reply('export-config-error', '导出配置失败: ' + e.message);
  }
});

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
    const stat = d.fsSync.statSync(filePath);
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
function registerTabSurfaces() {
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
function registerSettingsPanels() {
d.ipcMain.handle('vault-status', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  return { success: true, ...d.vaultStatusSnapshot() };
});

d.ipcMain.handle('vault-create', (event, payload = {}) => {
  if (!d.isMainSender(event)) return { success: false };
  const pw = typeof payload === 'string' ? payload : (payload && payload.masterPassword);
  if (!d.vaultPasswordOK(pw)) return { success: false, reason: 'bad-password' };
  return { success: true, ...d.createNewVault(pw) };
});

d.ipcMain.handle('vault-unlock', (event, payload = {}) => {
  if (!d.isMainSender(event)) return { success: false };
  const pw = typeof payload === 'string' ? payload : (payload && payload.masterPassword);
  if (!d.vaultPasswordOK(pw)) return { success: false, reason: 'bad-password' };
  return { success: true, ...d.unlockVault(pw) };
});

d.ipcMain.handle('vault-lock', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  if (d.vaultHandle) d.vaultHandle.lock();
  d.vaultHandle = null;
  return { success: true, ...d.vaultStatusSnapshot() };
});

d.ipcMain.handle('vault-list', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  if (!d.vaultHandle || d.vaultHandle.locked()) return { success: false, reason: 'locked' };
  return { success: true, ...d.vaultHandle.list() };
});

d.ipcMain.handle('vault-get', (event, id) => {
  if (!d.isMainSender(event)) return { success: false };
  if (!d.vaultHandle || d.vaultHandle.locked()) return { success: false, reason: 'locked' };
  const g = d.vaultHandle.get(String(id || ''));
  if (!g.ok) return { success: false, reason: g.reason };
  return { success: true, payload: g.payload, ...(d.vaultHandle.list().ok ? { label: d.vaultHandle.list().entries.find((e) => e.id === id)?.label } : {}) };
});

d.ipcMain.handle('vault-set', (event, payload = {}) => {
  if (!d.isMainSender(event)) return { success: false };
  if (!d.vaultHandle || d.vaultHandle.locked()) return { success: false, reason: 'locked' };
  const r = d.vaultHandle.set(String(payload.kind || ''), String(payload.label || ''), payload.payload);
  if (r.ok) d.persistVaultState();
  return { success: true, ...r };
});

d.ipcMain.handle('vault-update', (event, payload = {}) => {
  if (!d.isMainSender(event)) return { success: false };
  if (!d.vaultHandle || d.vaultHandle.locked()) return { success: false, reason: 'locked' };
  const r = d.vaultHandle.update(String(payload.id || ''), String(payload.kind || ''),
    String(payload.label || ''), payload.payload);
  if (r.ok) d.persistVaultState();
  return { success: true, ...r };
});

d.ipcMain.handle('vault-delete', (event, id) => {
  if (!d.isMainSender(event)) return { success: false };
  if (!d.vaultHandle || d.vaultHandle.locked()) return { success: false, reason: 'locked' };
  const r = d.vaultHandle.delete(String(id || ''));
  if (r.ok) d.persistVaultState();
  return { success: true, ...r };
});

// vault-rekey：修改主密码。传主密码 → PBKDF2 慢化重包裹；留空 → 生成新随机密钥
// 并重新写回系统安全存储。任一条目解密失败会整体中止，保持原状态。
d.ipcMain.handle('vault-rekey', (event, payload = {}) => {
  if (!d.isMainSender(event)) return { success: false };
  if (!d.vaultHandle || d.vaultHandle.locked()) return { success: false, reason: 'locked' };
  const pw = typeof payload === 'string' ? payload : (payload && payload.masterPassword);
  let key;
  let kdf;
  if (typeof pw === 'string' && pw.length > 0) {
    if (!d.vaultPasswordOK(pw)) return { success: false, reason: 'bad-password' };
    key = Buffer.from(pw, 'utf8');
    kdf = d.vaultCore.KDF_PBKDF2;
    d.vaultUsePasswordMode = true;
  } else {
    if (!d.safeStorage.isEncryptionAvailable()) {
      return { success: false, reason: 'password-required' };
    }
    key = d.crypto.randomBytes(32);
    kdf = d.vaultCore.KDF_HKDF;
    d.vaultUsePasswordMode = false;
  }
  const rr = d.vaultHandle.rekey(key, { kdf });
  if (!rr.ok) return { success: false, reason: rr.reason };
  d.persistVaultState();
  const keyPersisted = d.vaultUsePasswordMode ? true : d.persistVaultKey(key);
  return { success: true, keyPersisted, ...rr, ...d.vaultStatusSnapshot() };
});

// vault-export-backup：返回密文 JSON 文本（不含密钥/明文），供用户自行保存。
d.ipcMain.handle('vault-export-backup', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  if (!d.vaultHandle || d.vaultHandle.locked()) return { success: false, reason: 'locked' };
  const ex = d.vaultHandle.exportState();
  if (!ex.ok) return { success: false, reason: ex.reason };
  return { success: true, backup: JSON.stringify(ex.state) };
});

// vault-import-backup：合并同一主密钥包裹的备份密文；格式/密钥不匹配整体拒绝。
d.ipcMain.handle('vault-import-backup', (event, text) => {
  if (!d.isMainSender(event)) return { success: false };
  if (!d.vaultHandle || d.vaultHandle.locked()) return { success: false, reason: 'locked' };
  let state;
  try {
    state = JSON.parse(String(text || ''));
  } catch {
    return { success: false, reason: 'bad-state' };
  }
  const rr = d.vaultHandle.mergeFromState(state);
  if (rr.ok) d.persistVaultState();
  return { success: true, ...rr };
});

// ===== 站点数据清理 IPC =====
// 流程固定为：枚举 → 规划（纯函数）→ 用户确认 plan → 执行 → 审计。
// 执行只接受 filterSiteEntries 产出的 plan 对象（含 targets 白名单）。
d.ipcMain.handle('cleaner-enumerate', async (event) => {
  if (!d.isMainSender(event)) return { success: false };
  return { success: true, ...d.enumerateSiteStorage() };
});

d.ipcMain.handle('cleaner-plan', (event, payload = {}) => {
  if (!d.isMainSender(event)) return { success: false };
  const src = d.enumerateSiteStorage();
  const filtered = d.cleanerCore.filterSiteEntries(src.entries, {
    matchMode: payload.matchMode,
    host: payload.host,
    since: payload.since,
    storageTypes: payload.storageTypes,
  });
  if (!filtered.ok) return { success: false, ...filtered };
  return {
    success: true,
    ...filtered,
    storageTypes: payload.storageTypes || [],
    ...d.cleanerCore.summarizePlan(filtered, payload.actions || []),
  };
});

d.ipcMain.handle('cleaner-execute', async (event, plan) => {
  if (!d.isMainSender(event)) return { success: false };
  const res = await d.executeCleanPlan(plan);
  return { success: true, ...res };
});

d.ipcMain.handle('cleaner-audit', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  return { success: true, entries: d.cleanAuditLog.slice() };
});

d.ipcMain.handle('cleaner-prune-audit', (event, keep) => {
  if (!d.isMainSender(event)) return { success: false };
  const r = d.cleanerCore.pruneAuditLog(d.cleanAuditLog, Number(keep) || 0);
  if (r.ok) d.persistCleanAudit();
  return { success: true, ...r };
});

// ===== UA 覆盖策略 IPC =====
// get-ua-policy：返回当前策略、改写统计与生效 UA（含 default 时的自算值），
// 供 cosy://privacy 页展示。set/reset 都会持久化并立刻应用到 defaultSession
// （隔离会话下一次请求时也会吃到新策略，因为 resolveEffectiveUa 每次现算）。
d.ipcMain.handle('get-ua-policy', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  return {
    success: true,
    ...d.uaPolicyCore.policyToPlain(d.uaPolicyState),
    effectiveUa: d.resolveEffectiveUa(),
    overrideCount: d.uaOverrideCount,
    lastOverrideAt: d.uaLastOverrideAt,
  };
});

d.ipcMain.handle('set-ua-policy', (event, payload = {}) => {
  if (!d.isMainSender(event)) return { success: false };
  const next = d.uaPolicyCore.sanitizePolicy(payload);
  d.uaPolicyState = next;
  d.persistUaPolicyState();
  d.applyUaPolicyToSession(d.session.defaultSession);
  return {
    success: true,
    ...d.uaPolicyCore.policyToPlain(d.uaPolicyState),
    effectiveUa: d.resolveEffectiveUa(),
  };
});

d.ipcMain.handle('reset-ua-policy', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  d.uaPolicyState = { ...d.uaPolicyCore.DEFAULT_POLICY };
  d.uaOverrideCount = 0;
  d.uaLastOverrideAt = 0;
  d.persistUaPolicyState();
  d.applyUaPolicyToSession(d.session.defaultSession);
  return { success: true, ...d.uaPolicyCore.policyToPlain(d.uaPolicyState), effectiveUa: d.resolveEffectiveUa() };
});

// 随机预览一条 Chrome UA（只展示不改状态）：从内置池随机取。
// 仅主窗口可调用。
d.ipcMain.handle('preview-random-ua', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  const pool = d.uaPolicyCore && Array.isArray(d.uaPolicyCore.COMMON_CHROME_UAS) ? d.uaPolicyCore.COMMON_CHROME_UAS : [];
  if (pool.length === 0) return { success: false, reason: 'empty-pool' };
  const ua = d.uaPolicyCore.pickRandomChromeUa();
  return { success: true, ua: String(ua || '') };
});

// ===== 下载限速 IPC =====
d.ipcMain.handle('get-security-posture', (event) => {
  if (!d.isMainSender(event)) return { ok: false };
  const decisions = d.listPermissionDecisions();
  const riskyOrigins = new Set();
  for (const decision of decisions) {
    if (decision.state !== d.permissionGrants.STATE.ALLOW) continue;
    if ((d.permissionGrants.HIGH_RISK_WEIGHT[decision.permission] || 0) >= 2) riskyOrigins.add(decision.origin);
  }
  let criticalEvents = 0;
  for (const item of d.listSecurityEvents('', 200)) {
    if (item.severity === 'critical') criticalEvents += 1;
  }
  const cspStats = d.getCspReportStats();
  const headerStats = d.getHeaderGradeStats();
  d.loadCertExceptions();
  const report = d.securityPosture.scorePosture({
    httpsOnly: d.httpsOnlyEnabled,
    blockRules: (d.compiledCustomRules.host ? d.compiledCustomRules.host.size : 0)
      + (d.compiledCustomRules.glob ? d.compiledCustomRules.glob.length : 0)
      + (d.compiledCustomRules.path ? d.compiledCustomRules.path.length : 0),
    cspReports: Number(cspStats.totalHits) || 0,
    certExceptions: d.certExceptions.length,
    riskyOrigins: riskyOrigins.size,
    criticalEvents,
    headerGrades: headerStats.byGrade,
    expiredGrants: decisions.filter((decision) => decision.state === d.permissionGrants.STATE.EXPIRED).length,
  });
  return {
    ok: true,
    report,
    description: d.securityPosture.describePosture(report),
    worst: d.securityPosture.worstSeverity(report),
  };
});

d.ipcMain.handle('get-download-journal-export', (event, payload = {}) => {
  if (!d.isMainSender(event)) return { ok: false };
  const requested = Number.isInteger(payload.limit) && payload.limit > 0 ? payload.limit : d.downloadJournalModule.DEFAULT_MAX_ENTRIES;
  const entries = d.getDownloadJournal().snapshot().slice(0, requested);
  const exported = d.downloadJournalExport.buildJournalExport(entries);
  return {
    ok: true,
    export: exported,
    description: d.downloadJournalExport.describeExport(exported),
    leaked: d.downloadJournalExport.exportContainsLocalPaths(exported),
  };
});

d.ipcMain.handle('get-permission-risk-report', (event, payload = {}) => {
  if (!d.isMainSender(event)) return { ok: false };
  const requested = Number.isInteger(payload.limit) && payload.limit > 0 ? payload.limit : 50;
  const report = d.permissionRiskReport.buildPermissionReport(d.listPermissionDecisions(), { limit: requested });
  return {
    ok: true,
    report,
    description: d.permissionRiskReport.describePermissionReport(report),
    attention: d.permissionRiskReport.needsAttention(report),
  };
});

d.ipcMain.handle('get-download-rate-limit', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  return { success: true, bytesPerSecond: d.downloadRateLimit, kbps: Math.round(d.downloadRateLimit / 1024) };
});

d.ipcMain.handle('set-download-rate-limit', (event, payload = {}) => {
  if (!d.isMainSender(event)) return { success: false };
  const raw = Number(payload && payload.bytesPerSecond);
  if (!Number.isFinite(raw) || raw < 0) return { success: false, reason: 'invalid-rate' };
  d.downloadRateLimit = Math.floor(Math.min(raw, 1024 * 1024 * 1024)); // 封顶 1 GiB/s
  d.persistRateLimitState();
  // 已在进行中的下载项逐个应用新限速（未开始的在 will-download 时套用）。
  for (const d of d.downloads) {
    if (d.item && d.isItemValid) d.applyRateLimitToItem(d.item);
  }
  return { success: true, bytesPerSecond: d.downloadRateLimit };
});

d.ipcMain.handle('get-download-max-bytes', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  return { success: true, bytes: d.downloadMaxBytes };
});

d.ipcMain.handle('set-download-max-bytes', (event, payload = {}) => {
  if (!d.isMainSender(event)) return { success: false };
  const raw = Number(payload && payload.bytes);
  if (!Number.isFinite(raw) || raw < 0) return { success: false, reason: 'invalid-limit' };
  d.downloadMaxBytes = d.downloadSizeGuard.normalizeLimit(raw);
  try {
    const settingsPath = d.path.join(d.app.getPath('userData'), 'cosySettings.json');
    const cur = d.ledgerStore.readJSONStore(settingsPath, {});
    d.ledgerStore.writeJSONStore(settingsPath, d.sanitizeSettings(Object.assign({}, cur, { downloadMaxBytes: d.downloadMaxByteses })), { pretty: true });
  } catch (e) { console.error('保存下载体积上限失败:', e); }
  return { success: true, bytes: d.downloadMaxBytes };
});

d.ipcMain.handle('get-download-journal', (event, payload = {}) => {
  const requested = Number.isInteger(payload.limit) && payload.limit > 0 ? payload.limit : 50;
  const limit = Math.min(requested, d.downloadJournalModule.DEFAULT_MAX_ENTRIES);
  return d.getDownloadJournal().snapshot().slice(0, limit).map((entry) => ({
    id: entry.id,
    filename: entry.filename,
    host: entry.host,
    totalBytes: entry.totalBytes,
    receivedBytes: entry.receivedBytes,
    state: entry.state,
    startedAt: entry.startedAt,
    updatedAt: entry.updatedAt,
    resumable: entry.resumable === true,
    resumeReason: entry.resumeReason,
    resumeOffset: entry.resumeOffset,
    fileCheck: entry.fileCheck || d.downloadReconcileModule.VERDICT.SKIPPED,
    fileCheckReason: d.downloadReconcileModule.describeVerdict(entry.fileCheck || d.downloadReconcileModule.VERDICT.SKIPPED),
    fileBytes: Number.isFinite(entry.fileBytes) ? entry.fileBytes : null,
  }));
});

d.ipcMain.handle('reconcile-download-journal', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  const result = d.getDownloadJournal().reconcile(d.downloadJournalFileProbe());
  return {
    success: result.ok,
    summary: result.summary,
    description: d.downloadReconcileModule.summarizeReconcile(result.summary),
    changes: result.changes.length,
  };
});

d.ipcMain.handle('clear-download-journal', () => d.getDownloadJournal().clear());

// 崩溃横幅上的“强制刷新”：按 tabId 找到对应标签重载（无响应 / 连续崩溃后由用户手动触发）。
d.ipcMain.on('reload-tab-by-id', (event, tabId) => {
  if (!d.isMainSender(event)) return;
  const id = Number(tabId);
  const tab = d.tabs.find(t => t.view && t.view.webContents.id === id);
  const wc = tab?.view?.webContents;
  if (wc && !wc.isDestroyed()) {
    d.crashReloadCounts.delete(id);
    wc.reload();
  }
});

// 崩溃横幅上的“重新打开”：连续崩溃不再自动重载时，让用户在全新标签里重试该 URL。
d.ipcMain.on('reopen-tab-url', (event, url) => {
  if (!d.isMainSender(event)) return;
  if (typeof url === 'string' && d.isSafeUrl(url)) d.createNewTab(url);
});
}module.exports = { bindDeps, registerNetworkGuards, registerDownloadShelf, registerTabSurfaces, registerSettingsPanels };
