'use strict';
let d = {};

function persistHttpsExceptions() {
  if (d.httpsExceptionSaveTimer) clearTimeout(d.httpsExceptionSaveTimer);
  d.httpsExceptionSaveTimer = setTimeout(() => {
    try {
      d.ledgerStore.writeJSONStore(d.httpsExceptionStorePath, d.httpsExceptions.toJSON());
    } catch (e) { console.error('写入 HTTPS 例外失败:', e); }
  }, 300);
}

function isHttpExceptionHost(urlOrHost) {
  try {
    const host = String(urlOrHost || '').indexOf('://') >= 0
      ? new URL(urlOrHost).hostname
      : d.httpsOnlyCore.normalizeExceptionHost(urlOrHost);
    return !!host && d.httpsExceptions.has(host);
  } catch { return false; }
}

function loadUaPolicyStateFromDisk() {
  try {
    if (d.fsSync.existsSync(d.uaPolicyPath)) {
      const raw = JSON.parse(d.fsSync.readFileSync(d.uaPolicyPath, 'utf8'));
      d.uaPolicyState = d.uaPolicyCore.sanitizePolicy(raw);
    }
  } catch (e) { console.error('读取 UA 策略失败:', e); }
  try {
    if (d.fsSync.existsSync(d.rateLimitPath)) {
      const raw = JSON.parse(d.fsSync.readFileSync(d.rateLimitPath, 'utf8'));
      if (raw && Number.isFinite(raw.bytesPerSecond) && raw.bytesPerSecond >= 0) {
        d.downloadRateLimit = Math.floor(raw.bytesPerSecond);
      }
    }
  } catch (e) { console.error('读取下载限速失败:', e); }
}

function persistUaPolicyState() {
  try { atomicWriteJSON(d.uaPolicyPath, d.uaPolicyState); } catch (e) { console.error('写入 UA 策略失败:', e); }
}

function persistRateLimitState() {
  try { atomicWriteJSON(d.rateLimitPath, { bytesPerSecond: d.downloadRateLimit }); } catch (e) { console.error('写入下载限速失败:', e); }
}

function applyUaPolicyToSession(targetSession) {
  try {
    const effective = d.uaPolicyCore.resolveUa(d.uaPolicyState, d.generateUserAgent());
    targetSession.setUserAgent(effective);
  } catch (e) { console.error('应用 UA 策略失败:', e); }
}

function resolveEffectiveUa() {
  return d.uaPolicyCore.resolveUa(d.uaPolicyState, d.generateUserAgent());
}

function applyRateLimitToItem(item) {
  if (!item || !d.downloadRateLimit) return;
  try { item.setRate(d.downloadRateLimit); } catch {}
}

function atomicWriteJSON(filePath, obj) {
  const dir = d.path.dirname(filePath);
  const tmp = d.path.join(dir, '.' + d.path.basename(filePath) + '.tmp-' + process.pid + '-'
    + (d.atomicWriteSeq += 1) + '-' + Date.now().toString(36));
  let fd = null;
  try {
    fd = d.fsSync.openSync(tmp, 'wx', 0o600);
    d.fsSync.writeFileSync(fd, JSON.stringify(obj), 'utf8');
    d.fsSync.fsyncSync(fd);
    d.fsSync.closeSync(fd);
    fd = null;
    d.fsSync.renameSync(tmp, filePath);
  } catch (e) {
    if (fd !== null) { try { d.fsSync.closeSync(fd); } catch {} }
    try { d.fsSync.unlinkSync(tmp); } catch {}
    throw e;
  }
}

function loadVaultStateFromDisk() {
  try {
    if (d.fsSync.existsSync(d.vaultStorePath)) {
      d.vaultState = JSON.parse(d.fsSync.readFileSync(d.vaultStorePath, 'utf8'));
    }
  } catch (e) { console.error('读取保险库失败:', e); }
  try {
    if (d.fsSync.existsSync(d.cleanAuditPath)) {
      d.cleanAuditLog = JSON.parse(d.fsSync.readFileSync(d.cleanAuditPath, 'utf8'));
      if (!Array.isArray(d.cleanAuditLog)) d.cleanAuditLog = [];
    }
  } catch (e) { console.error('读取清理审计失败:', e); }
}

function persistVaultState() {
  if (!d.vaultState) return;
  try { atomicWriteJSON(d.vaultStorePath, d.vaultState); } catch (e) { console.error('写入保险库失败:', e); }
}

function persistCleanAudit() {
  try { atomicWriteJSON(d.cleanAuditPath, d.cleanAuditLog); } catch (e) { console.error('写入清理审计失败:', e); }
}

function persistVaultKey(keyBuf) {
  if (!d.safeStorage.isEncryptionAvailable()) {
    d.recordSecurityEvent('vault-key', 'critical',
      '系统加密不可用，拒绝以明文形式落盘保险库主密钥', 'vault');
    return false;
  }
  try {
    const wrapped = d.safeStorage.encryptString(keyBuf.toString('hex'));
    atomicWriteJSON(d.vaultKeyPath, { v: 1, s: 'safe', wrapped: wrapped.toString('base64') });
    return true;
  } catch (e) { console.error('写入保险库密钥失败:', e); return false; }
}

function maybeFallbackAfterUpgradeFailure(tab, errorCode, validatedURL) {
  if (!d.httpsOnlyEnabled) return false;
  if (!d.httpsOnlyCore.isFallbackableUpgradeError(errorCode)) return false;
  if (typeof validatedURL !== 'string' || !validatedURL.startsWith('https://')) return false;
  const httpUrl = d.httpsOnlyCore.downgradeHttpsUrlForFallback(validatedURL);
  if (!httpUrl) return false;
  let host = '';
  try {
    host = new URL(validatedURL).hostname.toLowerCase();
  } catch { return false; }
  if (!host || d.httpsExceptions.has(host)) return false;
  // 只有“该 http 地址确实会被我们升级成当前这个 https 地址”才允许回退，避免把
  // 用户手动输入 / 书签里的 https 地址错误地降级到明文。
  let repro;
  try {
    repro = d.httpsOnlyCore.upgradeHttpUrl(httpUrl);
  } catch { repro = null; }
  if (!repro || !repro.ok || repro.url !== validatedURL) return false;
  // 私网 / 回环本来就不会被升级，理论上进不来；再守一道。
  if (d.isPrivateNetworkHost(httpUrl)) return false;
  if (tab.httpsFallbackPrompting) return true; // 已有一个确认框在等，不叠加。
  tab.httpsFallbackPrompting = true;
  let choice = 0;
  try {
    const res = d.dialog.showMessageBoxSync(d.mainWindow, {
      type: 'warning',
      buttons: ['返回安全页面', '继续使用 HTTP（本次并记住该站点）'],
      defaultId: 0,
      cancelId: 0,
      title: '该站点不支持 HTTPS',
      message: `无法通过加密连接访问 ${host}`,
      detail: '服务器在 443 端口没有提供可用的 TLS（连接被拒绝 / 协议不匹配）。\n\n'
        + '如果继续，将以明文 HTTP 访问该站点，同网段中的其他人可能看到或篡改你与该站点之间传输的内容。\n'
        + '仅在你确认这是可信站点、且它确实只提供 HTTP 时才继续。',
      noLink: true,
    });
    choice = Number(res) || 0;
  } finally {
    tab.httpsFallbackPrompting = false;
  }
  if (choice !== 1) return true; // 用户选择留在错误页，已接手不再叠加通用错误页。
  d.httpsExceptions.add(host);
  persistHttpsExceptions();
  d.recordSecurityEvent('https-only', 'warn',
    `用户确认在不支持 HTTPS 的站点回退到明文 HTTP：${host}`, host);
  try {
    tab.view.webContents.loadURL(httpUrl);
  } catch (e) {
    console.error('HTTPS 回退加载失败:', e);
    return false;
  }
  return true;
}

function applyDarkMode(dark) {
  d.nativeTheme.themeSource = dark ? 'dark' : 'light';
  d.sendToRenderer('native-theme-changed', { dark: !!dark });
}

function bindDeps(x) { d = x; }

module.exports = { persistHttpsExceptions, isHttpExceptionHost, loadUaPolicyStateFromDisk, persistUaPolicyState, persistRateLimitState, applyUaPolicyToSession, resolveEffectiveUa, applyRateLimitToItem, atomicWriteJSON, loadVaultStateFromDisk, persistVaultState, persistCleanAudit, persistVaultKey, maybeFallbackAfterUpgradeFailure, applyDarkMode, bindDeps };
