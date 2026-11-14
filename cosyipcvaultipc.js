'use strict';

function registerVaultIpc(d) {
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
}

module.exports = { registerVaultIpc };
