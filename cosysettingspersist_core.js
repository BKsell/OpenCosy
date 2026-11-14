"use strict";

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
function persistSection(fileName, key, label) {
  const sectionPath = d.path.join(d.app.getPath('userData'), fileName);
  try {
    d[key] = writeSanitizedSection(sectionPath, d[key]);
  } catch (e) {
    console.error(label + '失败:', e);
  }
}
function restoreSection(fileName, key, label) {
  const sectionPath = d.path.join(d.app.getPath('userData'), fileName);
  try {
    const cleaned = readSanitizedSection(sectionPath);
    if (cleaned !== null) d[key] = cleaned;
  } catch (e) {
    console.error(label + '读取失败:', e);
  }
}
function saveBookmarks() {
  // r35：写盘前统一过 bookmarkguard——只落 http/https、title 去控制字符并限长、
  // 按 url 去重并收敛到硬上界。无论书签来自批量收藏 / 单条新增 / 导入，都在此收口，
  // 避免不可信标题或海量条目污染 bookmarks.json。
  persistSection('bookmarks.json', 'bookmarks', '保存书签');
}
function loadBookmarks() {
  // bookmarks.json 不是信任边界（可被手改 / 同步盘 / 恶意进程替换 / 崩溃截断）：
  // 非数组视为空，逐条做对象 / 字段 / scheme 校验，脏项丢弃，绝不把脏结构送进 UI。
  restoreSection('bookmarks.json', 'bookmarks', '读取书签');
}
function saveReadingList() {
  persistSection('readinglist.json', 'readingList', '保存稍后读');
}
function loadReadingList() {
  restoreSection('readinglist.json', 'readingList', '读取稍后读');
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

module.exports = { isPrivateNetworkHost, readStoredSettings, readSanitizedSection, writeSanitizedSection, saveBookmarks, loadBookmarks, saveReadingList, loadReadingList, saveSession, loadSession, clearSession, addToRecentlyClosed, getLastClosedTab };
