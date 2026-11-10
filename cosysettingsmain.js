const { getHttpStatusCode, getErrorMessage, getBrowserErrorText, isValidColor } = require('./cosysettingstext');

let d = {};
function bindDeps(x) {
  d = x;
}
function sanitizeSpellcheckLanguages(raw) {
  if (!Array.isArray(raw)) return d.DEFAULT_SPELLCHECK_LANGUAGES.slice();
  const out = [];
  for (const lang of raw) {
    if (typeof lang !== 'string' || !d.ALLOWED_SPELLCHECK_LANGUAGES.includes(lang)) continue;
    if (!out.includes(lang)) out.push(lang);
    if (out.length >= d.MAX_SPELLCHECK_LANGUAGES) break;
  }
  return out.length ? out : d.DEFAULT_SPELLCHECK_LANGUAGES.slice();
}
function applySpellcheckSettings() {
  try {
    const ses = d.session.defaultSession;
    ses.setSpellCheckerEnabled(d.spellcheckEnabled);
    if (!d.spellcheckEnabled) return;
    const available = new Set(ses.availableSpellCheckerLanguages || []);
    let langs = d.spellcheckLanguages.filter(l => available.has(l));
    if (!langs.length) {
      langs = d.DEFAULT_SPELLCHECK_LANGUAGES.filter(l => available.has(l));
    }
    if (langs.length) ses.setSpellCheckerLanguages(langs);
  } catch (e) {
    console.error('应用拼写检查设置失败:', e);
  }
}
function readPersistedSettings() {
  try {
    const p = d.path.join(d.app.getPath('userData'), 'cosySettings.json');
    return d.ledgerStore.readJSONStore(p, {});
  } catch (e) {
    console.error('启动时读取设置失败:', e);
  }
  return {};
}
function isMainSender(event) {
  if (!d.mainWindow || !event || event.sender !== d.mainWindow.webContents) return false;
  const frame = event.senderFrame;
  if (!frame) return false;
  try {
    return frame.parent === null && frame.top === frame;
  } catch {
    return false;
  }
}
function isInternalFileFrame(frameUrl) {
  if (typeof frameUrl !== 'string' || !frameUrl.startsWith('file:')) return false;
  let filePath;
  try {
    filePath = require('url').fileURLToPath(frameUrl);
  } catch {
    return false;
  }
  return d.winPolicy.isInsideRoot(filePath, __dirname);
}
function sendToRenderer(channel, ...args) {
  if (d.mainWindow && !d.mainWindow.isDestroyed()) {
    d.mainWindow.webContents.send(channel, ...args);
  }
}
function shelfSnapshot() {
  return d.downloadShelf.buildShelfSnapshot(d.downloads, d.downloadShelf.ShelfLimits).items;
}
function sendShelf() {
  persistDownloads();
  sendToRenderer('download-shelf', d.downloadShelf.buildShelfSnapshot(d.downloads, d.downloadShelf.ShelfLimits));
}
function downloadsStorePath() {
  return d.path.join(d.app.getPath('userData'), 'downloads.json');
}
function persistDownloads() {
  try {
    const items = (d.downloads || []).slice(0, d.MAX_PERSISTED_DOWNLOADS)
      .map(d => d.downloadShelf.sanitizeDownloadRecord(d, d.downloadShelf.ShelfLimits));
    d.ledgerStore.writeJSONStore(downloadsStorePath(), items, { pretty: true });
  } catch (e) {
    d.recordSecurityEvent('downloads-persist', 'error',
      '下载台账落盘失败: ' + String((e && e.message) || e).slice(0, 160), '');
  }
}
function notifyDownloadResult(kind, info) {
  try {
    d.downloadNotify.notifyDownload(kind, d.downloadNotifyDeps(), info);
  } catch (notifyErr) {
    d.recordSecurityEvent('download-notify', 'info',
      `系统通知失败: ${String(notifyErr && notifyErr.message || notifyErr)}`,
      d.originOfContents(d.webContents));
  }
}
function getSafeDirs() {
  return [
    d.app.getPath('downloads'), d.app.getPath('documents'),
    d.app.getPath('desktop'), d.app.getPath('pictures'),
    d.app.getPath('videos'), d.app.getPath('music'), __dirname,
  ];
}
function isInSafeDirs(filePath) {
  return getSafeDirs().some(dir => isPathInDir(filePath, dir));
}
function isSafeUrl(url) {
  try {
    const parsed = new URL(url);
    return d.ALLOWED_PROTOCOLS.has(parsed.protocol);
  } catch {
    return false;
  }
}
function sanitizePath(inputPath, baseDir) {
  const resolved = d.path.resolve(baseDir, inputPath);
  const normalized = d.path.normalize(resolved);
  if (!isPathInDir(normalized, baseDir)) return null;
  return normalized;
}
function isPathInDir(filePath, dir) {
  return d.pathContain.isContained(dir, filePath, { realpath: realpathForContainment }).ok;
}
function realpathForContainment(p) {
  try {
    return d.fsSync.realpathSync.native(p);
  } catch {
    return null;
  }
}
function getCurrentTabWebContents() {
  const tab = d.tabs[d.currentTabIndex];
  return tab?.view?.webContents || null;
}
function toggleDevTools() {
  const wc = getCurrentTabWebContents();
  if (wc) wc.toggleDevTools();
}
function goHome() {
  const tab = d.tabs[d.currentTabIndex];
  if (tab) {
    tab.url = 'cosy://newtab';
    d.loadTabContent(tab);
    sendToRenderer('tab-updated', { id: tab.id, url: tab.url, title: '新标签页' });
  }
}
function addToHistory(url, title) {
  // r34：历史写入统一走 historyguard 内核——只记录 http/https 导航，title 去控制
  // 字符 / 压空白 / 截断上界，URL 长度有界，同 URL 合并窗内只刷新时间戳（抑制刷新
  // 抖动与写放大）。内核用传入的 {items: history} 直接在历史数组上原地改写。
  const verdict = d.historyGuard.decideHistoryWrite(
    { items: d.history }, { url, title }, Date.now());
  if (verdict.decision === d.historyGuard.DECISION_SKIP) return;
  // 应用侧维持比内核安全上限（5000）更紧的展示上界 1000，超出淘汰最旧。
  if (d.history.length > d.MAX_HISTORY_ENTRIES) d.history = d.history.slice(0, d.MAX_HISTORY_ENTRIES);
  saveHistory();
}
function saveHistory() {
  const historyPath = d.path.join(d.app.getPath('userData'), 'history.json');
  try {
    d.ledgerStore.writeJSONStore(historyPath, d.history, { pretty: true });
  } catch (e) {
    console.error('保存历史记录失败:', e);
  }
}
function loadHistory() {
  const historyPath = d.path.join(d.app.getPath('userData'), 'history.json');
  try {
    if (!d.fsSync.existsSync(historyPath)) return;
    // history.json 是本地文件、也可能被外部程序 / 旧版本写坏：解析结果必须是数组，
    // 且每条都重新过内核净化（非 http/https、无法解析、标题含控制字符的一律丢弃 /
    // 清洗），时间戳必须为有限非负数，否则该条丢弃。绝不信任磁盘上的结构。
    // 有界读取：损坏 / 被撑大的文件回落为 null，下面按“非数组”清空，绝不整读撑爆主进程。
    const parsed = d.ledgerStore.readJSONStore(historyPath, null);
    if (!Array.isArray(parsed)) {
      d.history = [];
      return;
    }
    const clean = [];
    for (const item of parsed) {
      if (!item || typeof item !== 'object') continue;
      const su = d.historyGuard.sanitizeHistoryUrl(item.url);
      if (!su.ok) continue;
      if (typeof item.timestamp !== 'number' || !Number.isFinite(item.timestamp)
          || item.timestamp < 0) continue;
      clean.push({
        url: su.url,
        title: d.historyGuard.sanitizeHistoryTitle(item.title),
        timestamp: item.timestamp,
      });
      if (clean.length >= d.MAX_HISTORY_ENTRIES) break;
    }
    d.history = clean;
  } catch (e) {
    console.error('读取历史记录失败:', e);
  }
}
function readSanitizedSection(sectionPath) {
  if (!d.fsSync.existsSync(sectionPath)) return null;
  const parsed = d.ledgerStore.readJSONStore(sectionPath, null);
  if (parsed === null) return null;
  return d.bookmarkGuard.sanitizeBookmarkList(parsed, Date.now()).items;
}
function writeSanitizedSection(sectionPath, items) {
  const cleaned = d.bookmarkGuard.sanitizeBookmarkList(items, Date.now()).items;
  d.ledgerStore.writeJSONStore(sectionPath, cleaned, { pretty: true });
  return cleaned;
}
function saveBookmarks() {
  const bookmarksPath = d.path.join(d.app.getPath('userData'), 'bookmarks.json');
  try {
    // r35：写盘前统一过 bookmarkguard——只落 http/https、title 去控制字符并限长、
    // 按 url 去重并收敛到硬上界。无论书签来自批量收藏 / 单条新增 / 导入，都在此收口，
    // 避免不可信标题或海量条目污染 bookmarks.json。
    d.bookmarks = writeSanitizedSection(bookmarksPath, d.bookmarks);
  } catch (e) {
    console.error('保存书签失败:', e);
  }
}
function loadBookmarks() {
  const bookmarksPath = d.path.join(d.app.getPath('userData'), 'bookmarks.json');
  try {
    // bookmarks.json 不是信任边界（可被手改 / 同步盘 / 恶意进程替换 / 崩溃截断）：
    // 非数组视为空，逐条做对象 / 字段 / scheme 校验，脏项丢弃，绝不把脏结构送进 UI。
    const cleaned = readSanitizedSection(bookmarksPath);
    if (cleaned !== null) d.bookmarks = cleaned;
  } catch (e) {
    console.error('读取书签失败:', e);
  }
}
function saveReadingList() {
  const rlPath = d.path.join(d.app.getPath('userData'), 'readinglist.json');
  try {
    d.readingList = writeSanitizedSection(rlPath, d.readingList);
  } catch (e) {
    console.error('保存稍后读失败:', e);
  }
}
function loadReadingList() {
  const rlPath = d.path.join(d.app.getPath('userData'), 'readinglist.json');
  try {
    const cleaned = readSanitizedSection(rlPath);
    if (cleaned !== null) d.readingList = cleaned;
  } catch (e) {
    console.error('读取稍后读失败:', e);
  }
}
function saveSession() {
  try {
    const sessionPath = d.path.join(d.app.getPath('userData'), 'session.json');
    // r35：会话条目先映射成 {url,title}，再交给 restoreguard 统一净化（仅 http/https、
    // title 去控制字符并限长）并截断到恢复上界，替代旧实现“只过滤 url、title 原样写”。
    const raw = d.tabs
      .filter(tab => !String(tab.url || '').startsWith('cosy://'))
      .map(tab => ({ url: tab.url, title: tab.title }));
    const sessionTabs = d.restoreGuard.sanitizeSessionList(raw).tabs;
    d.ledgerStore.writeJSONStore(sessionPath, sessionTabs, { pretty: true });
  } catch (e) {
    console.error('保存会话失败:', e);
  }
}
function loadSession() {
  try {
    const sessionPath = d.path.join(d.app.getPath('userData'), 'session.json');
    if (d.fsSync.existsSync(sessionPath)) {
      const parsed = d.ledgerStore.readJSONStore(sessionPath, null);
      if (parsed === null) return null;
      // 逐条做对象 / url / title 校验：旧实现只判 Array.isArray 就 filter(isSafeUrl)，
      // null / 数字 / 嵌套数组会让恢复时访问 tab.title 抛异常并阻断全部标签恢复。
      const { tabs: restored } = d.restoreGuard.sanitizeSessionList(parsed);
      if (restored.length > 0) return restored;
    }
  } catch (e) {
    console.error('读取会话失败:', e);
  }
  return null;
}
function clearSession() {
  try {
    const sessionPath = d.path.join(d.app.getPath('userData'), 'session.json');
    if (d.fsSync.existsSync(sessionPath)) d.fsSync.unlinkSync(sessionPath);
  } catch (e) {
    console.error('清除会话失败:', e);
  }
}
function addToRecentlyClosed(tab) {
  if (!tab || !tab.url || String(tab.url).startsWith('cosy://')) return;
  // r35：入栈条目走 restoreguard——仅 http/https、title 去控制字符、closedAt 必须
  // 是有限毫秒时间戳，超深由内核淘汰最旧，替代旧实现对远端 title 的裸 push。
  const state = d.restoreGuard.createRecentlyClosedState(d.recentlyClosedTabs);
  const r = d.restoreGuard.pushRecentlyClosed(state, {
    url: tab.url, title: tab.title, closedAt: Date.now(),
  }, Date.now());
  if (r.status === 'pushed') d.recentlyClosedTabs = state.items;
}
function getLastClosedTab() {
  // 条目在 addToRecentlyClosed 入栈时已逐条净化，这里维持原“弹出栈顶”语义。
  if (d.recentlyClosedTabs.length === 0) return null;
  return d.recentlyClosedTabs.pop();
}
function isPrivateNetworkHost(url) {
  try {
    // 主机名归一、IPv4 分段与私网段判断统一走 hostmatch 内核（无正则）。
    return d.hostMatch.isPrivateHostname(new URL(url).hostname);
  } catch { return false; }
}
function readStoredSettings() {
  try {
    const p = d.path.join(d.app.getPath('userData'), 'cosySettings.json');
    return d.ledgerStore.readJSONStore(p, {});
  } catch (e) { console.error('读取设置失败:', e); }
  return {};
}
module.exports = { bindDeps, sanitizeSpellcheckLanguages, applySpellcheckSettings, readPersistedSettings, isMainSender, isInternalFileFrame, sendToRenderer, shelfSnapshot, sendShelf, downloadsStorePath, persistDownloads, notifyDownloadResult, getSafeDirs, isInSafeDirs, getHttpStatusCode, getErrorMessage, getBrowserErrorText, isSafeUrl, sanitizePath, isPathInDir, realpathForContainment, isValidColor, getCurrentTabWebContents, toggleDevTools, goHome, addToHistory, saveHistory, loadHistory, saveBookmarks, loadBookmarks, saveReadingList, loadReadingList, saveSession, loadSession, clearSession, addToRecentlyClosed, getLastClosedTab, isPrivateNetworkHost, readStoredSettings };
