'use strict';
function registerNetworkGuards(d) {
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

module.exports = { registerNetworkGuards };
