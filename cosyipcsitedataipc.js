'use strict';

let d = {};

function bindDeps(x) {
  d = x;
}

function registerSiteDataIpc() {
d.ipcMain.handle('list-site-data', async (event, payload = {}) => {
  if (!d.isMainSender(event)) return { success: false, error: 'Unauthorized' };
  const query = typeof payload.query === 'string'
    ? payload.query.trim().toLowerCase().slice(0, d.SITE_DATA_SEARCH_MAX) : '';
  try {
    const cookies = await d.session.defaultSession.cookies.get({});
    const groups = new Map();
    for (const c of cookies) {
      const domain = d.normalizeCookieDomain(c.domain);
      if (!domain) continue;
      if (query && !domain.toLowerCase().includes(query)) continue;
      let row = groups.get(domain);
      if (!row) {
        row = { domain, count: 0, secureCount: 0, httpOnlyCount: 0, sessionCount: 0, names: [] };
        groups.set(domain, row);
      }
      row.count++;
      if (c.secure) row.secureCount++;
      if (c.httpOnly) row.httpOnlyCount++;
      if (c.session) row.sessionCount++;
      if (row.names.length < d.SITE_DATA_MAX_NAMES && !row.names.includes(c.name)) {
        row.names.push(c.name);
      }
    }
    const rows = Array.from(groups.values())
      .sort((a, b) => b.count - a.count || a.domain.localeCompare(b.domain))
      .slice(0, d.SITE_DATA_MAX_ROWS);
    return { success: true, rows, totalCookies: cookies.length, truncated: groups.size > rows.length };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// 查看某个域名（含其子域）下的全部 Cookie。
d.ipcMain.handle('get-site-cookies', async (event, payload = {}) => {
  if (!d.isMainSender(event)) return { success: false, error: 'Unauthorized' };
  const domain = d.normalizeCookieDomain(payload.domain);
  if (!domain) return { success: false, error: 'Invalid domain' };
  try {
    const all = await d.session.defaultSession.cookies.get({});
    const matched = all.filter(c => {
      const d = d.normalizeCookieDomain(c.domain);
      return d.hostMatch.hostEqualsOrSubdomain(d, domain);
    }).map(d.pickCookieFields);
    return { success: true, domain, cookies: matched };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// 删除单条 Cookie（按 name + domain + path 精确定位）。
d.ipcMain.handle('delete-site-cookie', async (event, payload = {}) => {
  if (!d.isMainSender(event)) return { success: false, error: 'Unauthorized' };
  const name = payload.name;
  const domain = d.normalizeCookieDomain(payload.domain);
  if (typeof name !== 'string' || !name || !domain) {
    return { success: false, error: 'Invalid cookie' };
  }
  try {
    const all = await d.session.defaultSession.cookies.get({});
    const target = all.find(c => c.name === name &&
      d.normalizeCookieDomain(c.domain) === domain &&
      (!payload.path || c.path === payload.path));
    if (!target) return { success: false, error: 'Cookie 不存在或已过期' };
    await d.removeCookieEntry(target);
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// 删除某个域名及其全部子域下的 Cookie。
d.ipcMain.handle('delete-site-cookies', async (event, payload = {}) => {
  if (!d.isMainSender(event)) return { success: false, error: 'Unauthorized' };
  const domain = d.normalizeCookieDomain(payload.domain);
  if (!domain) return { success: false, error: 'Invalid domain' };
  try {
    const all = await d.session.defaultSession.cookies.get({});
    const targets = all.filter(c => {
      const d = d.normalizeCookieDomain(c.domain);
      return d.hostMatch.hostEqualsOrSubdomain(d, domain);
    });
    let removed = 0;
    for (const c of targets) {
      try { await d.removeCookieEntry(c); removed++; } catch { /* 过期/httponly 删除失败的跳过 */ }
    }
    return { success: true, removed };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// 清空某域名的本地存储（Cookie/LocalStorage/IndexedDB/ServiceWorker 等）。
d.ipcMain.handle('clear-site-storage', async (event, payload = {}) => {
  if (!d.isMainSender(event)) return { success: false, error: 'Unauthorized' };
  const domain = d.normalizeCookieDomain(payload.domain);
  if (!domain || !/^[a-z0-9.-]+$/i.test(domain)) {
    return { success: false, error: 'Invalid domain' };
  }
  try {
    for (const scheme of ['https', 'http']) {
      await d.session.defaultSession.clearStorageData({
        origin: `${scheme}://${domain}`,
        storages: d.SITE_DATA_STORAGES,
      });
    }
    return { success: true, domain };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// 打印当前标签页（Ctrl+P）。只作用于活动标签的网页内容。
d.ipcMain.handle('print-current-tab', (event) => {
  if (!d.isMainSender(event)) return { success: false, error: 'Unauthorized' };
  const tab = d.tabs[d.currentTabIndex];
  const wc = tab && tab.view && tab.view.webContents;
  if (!wc || wc.isDestroyed()) return { success: false, error: 'No active page' };
  try {
    wc.print({ silent: false, printBackground: true }, () => {});
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
});
}

module.exports = { bindDeps, registerSiteDataIpc };
