'use strict';

const protocolIpc = require('./cosyipcprotocol');
const messagingIpc = require('./cosyipcmessaging');
const searchIpc = require('./cosyipcsearch');
const cosyipcextinstall = require('./cosyipcextinstall');
const cosycertipc = require('./cosycertipc');
const siteDataIpc = require('./cosyipcsitedataipc');

let d = {};

function bindDeps(x) {
  d = x;
  protocolIpc.bindDeps(x);
  messagingIpc.bindDeps(x);
  searchIpc.bindDeps(x);
  cosyipcextinstall.bindDeps(x);
  cosycertipc.bindDeps(x);
  siteDataIpc.bindDeps(x);
}

function registerProtocolIpc() {
  protocolIpc.registerProtocolIpc();
}

function bootstrapRuntimeState() {
  protocolIpc.bootstrapRuntimeState();
}

function registerMessagingIpc() {
  messagingIpc.registerMessagingIpc();
}

function registerFindIpc() {
  searchIpc.registerFindIpc();
}

function registerTabOverviewIpc() {
  searchIpc.registerTabOverviewIpc();
}

function registerExtensionIpc() {
  cosyipcextinstall.registerExtensionIpc();
}

function registerCertificateIpc() {
  cosycertipc.registerCertificateIpc();
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

function installCertificateErrorHandler() {
d.app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
  try {
    if (d.certExceptionAllowed(url, certificate)) {
      event.preventDefault();
      callback(true);
      return;
    }
    event.preventDefault();
    callback(false);

    const verdict = d.certGuard.classifyCertError({ url, error, certificate });
    if (!verdict.host) return;
    // 只为主框架导航弹拦截页；子资源（图片/脚本等）证书错误静默阻止即可。
    let isMainFrame = false;
    try {
      const cur = webContents.getURL ? webContents.getURL() : '';
      isMainFrame = !cur || d.certGuard.normalizeHost(cur) === verdict.host;
    } catch { isMainFrame = true; }
    if (!isMainFrame) return;

    const nonce = d.makeCertChallenge(verdict, webContents.id);
    d.sendToRenderer('cert-error-blocked', {
      nonce,
      url: String(url).slice(0, 2048),
      host: verdict.host,
      code: verdict.code,
      overridable: verdict.overridable,
      title: verdict.title,
      detail: verdict.detail,
      cert: verdict.cert,
      shortFingerprint: d.certGuard.shortFingerprint(verdict.cert ? verdict.cert.fingerprint : ''),
    });
  } catch {
    // 任何意外都 fail-closed，绝不因异常而默认放行。
    try { event.preventDefault(); } catch {}
    try { callback(false); } catch {}
  }
});

d.ipcMain.handle('approve-cert-exception', (event, payload = {}) => {
  const challenge = d.consumeCertChallenge(payload.nonce);
  if (!challenge) return { ok: false, error: '挑战已过期或无效，请重新访问' };
  const verdict2 = d.certGuard.errorInfo(challenge.code);
  if (!verdict2.overridable) return { ok: false, error: '该证书错误不可绕过' };
  const ok = d.addCertException(challenge.host, {
    fingerprint: challenge.fingerprint ? `sha256/${challenge.fingerprint}` : '',
    subjectName: '',
    issuerName: '',
  }, challenge.code);
  if (!ok) return { ok: false, error: '例外记录失败' };
  // 放行后重新加载对应标签；找不到则只记录、不导航。
  try {
    const target = d.webContents.fromId(challenge.webContentsId);
    if (target && !target.isDestroyed()) {
      setImmediate(() => { try { target.reload(); } catch {} });
    }
  } catch {}
  d.sendToRenderer('cert-exception-updated', d.getCertExceptionStats());
  return { ok: true };
});

d.ipcMain.handle('list-cert-exceptions', (event, payload = {}) => ({
  entries: d.listCertExceptionEntries(payload.limit),
  stats: d.getCertExceptionStats(),
}));

d.ipcMain.handle('remove-cert-exception', (event, payload = {}) => {
  d.removeCertException(payload.host, payload.fingerprint);
  d.sendToRenderer('cert-exception-updated', d.getCertExceptionStats());
  return { ok: true };
});

d.ipcMain.handle('clear-cert-exceptions', () => {
  d.clearCertExceptions();
  d.sendToRenderer('cert-exception-updated', d.getCertExceptionStats());
  return { ok: true };
});

d.ipcMain.handle('get-cert-exception-stats', () => d.getCertExceptionStats());
}

function registerSiteDataIpc() {
  siteDataIpc.registerSiteDataIpc();
}

module.exports = {
  bindDeps,
  registerProtocolIpc,
  bootstrapRuntimeState,
  registerMessagingIpc,
  registerFindIpc,
  registerTabOverviewIpc,
  registerExtensionIpc,
  registerCertificateIpc,
  registerBlockRulesIpc,
  registerSearchSuggestIpc,
  registerSiteDataIpc,
  installCertificateErrorHandler,
};
