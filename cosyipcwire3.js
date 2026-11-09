'use strict';

const { registerSiteDataIpc } = require('./cosyipcsitedataipc');

let d = {};

function bindDeps(x) {
  d = x;
}

function registerBlockRulesIpc() {
d.ipcMain.handle('get-block-rules', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  return { success: true, enabled: d.blockTrackers, rules: d.customRulesSnapshot() };
});

d.ipcMain.handle('add-block-rule', (event, raw) => {
  if (!d.isMainSender(event)) return { success: false };
  const res = d.blockRules.addRule(d.customRules, String(raw || ''));
  if (res.ok) {
    const saved = d.persistCustomRules();
    if (!saved.ok) return { success: false, ok: false, reason: saved.reason };
  }
  return { success: true, ...res, count: d.blockRules.ruleCount(d.customRules) };
});

d.ipcMain.handle('remove-block-rule', (event, raw) => {
  if (!d.isMainSender(event)) return { success: false };
  const removed = d.blockRules.removeRule(d.customRules, String(raw || ''));
  if (removed) d.persistCustomRules();
  return { success: true, removed, count: d.blockRules.ruleCount(d.customRules) };
});

d.ipcMain.handle('import-block-rules', (event, text) => {
  if (!d.isMainSender(event)) return { success: false };
  const res = d.blockRules.importRulesText(d.customRules, String(text || ''));
  const saved = d.persistCustomRules();
  if (!saved.ok) return { success: false, ...res, reason: saved.reason };
  return { success: true, ...res, count: d.blockRules.ruleCount(d.customRules) };
});

d.ipcMain.handle('export-block-rules', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  return { success: true, text: d.blockRules.exportRulesText(d.customRules) };
});

d.ipcMain.handle('clear-block-rules', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  d.customRules.host = [];
  d.customRules.glob = [];
  d.customRules.path = [];
  d.persistCustomRules();
  return { success: true, count: 0 };
});
}

function registerSearchSuggestIpc() {
d.ipcMain.handle('get-search-suggestions', async (event, payload = {}) => {
  if (!d.isMainSender(event)) return { success: false, suggestions: [] };
  const q = typeof payload.q === 'string' ? payload.q.trim() : '';
  if (!q || q.length > d.SUGGEST_MAX_CHARS) return { success: false, suggestions: [] };
  // 已经是完整 URL / 内置协议时不给搜索建议，交给历史/书签补全。
  if (/^[a-z][a-z0-9+.-]*:/i.test(q) || q.startsWith('//')) return { success: true, suggestions: [] };
  const suggestions = await d.fetchSearchSuggestions(q);
  return { success: true, suggestions };
});

// —— 默认搜索引擎（searchprovider 内核）——
d.ipcMain.handle('get-search-provider', (event) => {
  if (!d.isMainSender(event)) return { success: false };
  return {
    success: true,
    providerId: d.searchProviderId,
    providers: d.searchProvider.providerSummary(),
    defaultId: d.searchProvider.DEFAULT_PROVIDER_ID,
  };
});

d.ipcMain.handle('set-search-provider', (event, payload = {}) => {
  if (!d.isMainSender(event)) return { success: false };
  const id = typeof payload === 'string' ? payload : (payload && payload.providerId);
  const chosen = d.searchProvider.sanitizeProviderChoice(id);
  // 未知 id 被收敛回默认：此时不落盘（脏数据不污染设置），仅返回当前值。
  if (chosen === id || id === d.searchProvider.DEFAULT_PROVIDER_ID) {
    d.searchProviderId = chosen;
    try {
      const settingsPath = d.path.join(d.app.getPath('userData'), 'cosySettings.json');
      const cur = d.ledgerStore.readJSONStore(settingsPath, {});
      const clean = d.sanitizeSettings(Object.assign({}, cur, { searchEngine: chosen }));
      d.ledgerStore.writeJSONStore(settingsPath, clean, { pretty: true });
      d.recordSecurityEvent('settings-search-provider', 'info',
        `默认搜索引擎切换为 ${chosen}`, 'main');
    } catch (e) {
      d.recordSecurityEvent('settings-search-provider', 'warn',
        `搜索引擎设置落盘失败: ${e.message}`, 'main');
    }
  }
  return { success: true, providerId: d.searchProviderId };
});
}

module.exports = { bindDeps, registerBlockRulesIpc, registerSiteDataIpc, registerSearchSuggestIpc };
