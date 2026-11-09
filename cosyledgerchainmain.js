let d = {};
function bindDeps(x) {
  d = x;
}
function loadHttpsExceptions() {
  if (d.httpsExceptionsLoaded) return;
  d.httpsExceptionsLoaded = true;
  try {
    d.httpsExceptions.load(d.ledgerStore.readJSONStore(d.httpsExceptionStorePath, {}));
  } catch (e) { console.error('读取 HTTPS 例外失败:', e); }
}
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
function loadPnaLedger() {
  if (d.pnaLedgerLoaded) return;
  d.pnaLedgerLoaded = true;
  try {
    const data = d.ledgerStore.readJSONStore(d.pnaLedgerStorePath, {});
    const rows = Array.isArray(data && data.rows) ? data.rows : [];
    for (const r of rows) {
      if (!r || typeof r.host !== 'string') continue;
      d.pnaLedger.set(r.host, {
        host: String(r.host).slice(0, 255),
        space: String(r.space || 'private').slice(0, 32),
        hits: Number(r.hits) || 1,
        lastTime: Number(r.lastTime) || Date.now(),
      });
    }
  } catch {}
}
function persistPnaLedger() {
  if (d.pnaLedgerSaveTimer) clearTimeout(d.pnaLedgerSaveTimer);
  d.pnaLedgerSaveTimer = setTimeout(() => {
    try {
      const rows = [...d.pnaLedger.values()];
      d.ledgerStore.writeJSONStore(d.pnaLedgerStorePath, { version: 1, rows });
    } catch {}
  }, 400);
}
function pnaLedgerStats() {
  let blocked = 0;
  for (const v of d.pnaLedger.values()) blocked += v.hits;
  return { hosts: d.pnaLedger.size, blocked };
}
function recordPnaBlock(details, verdict) {
  loadPnaLedger();
  const host = String(verdict.targetHost || '').slice(0, 255);
  if (!host) return;
  const cur = d.pnaLedger.get(host) || { host, space: verdict.targetSpace || 'private', hits: 0, lastTime: 0 };
  cur.hits += 1;
  cur.lastTime = Date.now();
  cur.space = verdict.targetSpace || cur.space;
  d.pnaLedger.set(host, cur);
  if (d.pnaLedger.size > d.MAX_PNA_LEDGER) {
    const oldest = [...d.pnaLedger.entries()]
      .sort((a, b) => a[1].lastTime - b[1].lastTime)[0][0];
    d.pnaLedger.delete(oldest);
  }
  persistPnaLedger();
  d.sendToRenderer('pna-blocked-updated', pnaLedgerStats());
}
function loadFpLedger() {
  if (d.fpLedgerLoaded) return;
  d.fpLedgerLoaded = true;
  try {
    d.fpLedger.load(d.ledgerStore.readJSONStore(d.fpLedgerStorePath, {}));
  } catch {}
}
function persistFpLedger() {
  if (d.fpLedgerSaveTimer) clearTimeout(d.fpLedgerSaveTimer);
  d.fpLedgerSaveTimer = setTimeout(() => {
    try {
      d.ledgerStore.writeJSONStore(d.fpLedgerStorePath, d.fpLedger.toJSON());
    } catch {}
  }, 400);
}
function applyWebRtcPolicy() {
  // WebRTC ICE 候选默认可能暴露内网/真实公网 IP（可穿透 VPN）。
  // strict 只用默认公网接口；balanced 允许 mDNS 混淆候选；legacy 不干预。
  try {
    d.session.defaultSession.setWebRTCIPHandlingPolicy(d.fpGuard.resolveWebRtcPolicy(d.webrtcMode));
  } catch {}
}
function loadDohLedger() {
  if (d.dohLedgerLoaded) return;
  d.dohLedgerLoaded = true;
  try {
    d.dohLedger.load(d.ledgerStore.readJSONStore(d.dohStorePath, {}));
  } catch {}
}
function persistDohLedger() {
  if (d.dohSaveTimer) clearTimeout(d.dohSaveTimer);
  d.dohSaveTimer = setTimeout(() => {
    try {
      d.ledgerStore.writeJSONStore(d.dohStorePath, d.dohLedger.toJSON());
    } catch {}
  }, 400);
}
function dohStatus() {
  return {
    mode: d.dohMode,
    provider: d.dohProvider,
    active: d.dohActive,
    events: d.dohLedger.list().slice(0, 50),
  };
}
function applyWebRequestFiltering(targetSession, options) {
  // options.logRequests 仅控制是否把请求量计入默认会话的连接统计（分区不重复计数）；
  // 阻断 / 升级 / 安全审计在所有会话上行为一致。
  const logRequests = !!(options && options.logRequests);
  const noteAttempt = logRequests ? d.recordRequestAttempt : () => {};
  d.requestPipeline.applyPipeline(targetSession.webRequest, d.buildRequestPipelineDeps(), noteAttempt);
}
function originOfContents(contents) {
  if (!contents || typeof contents.getURL !== 'function') return '';
  return d.urlResolve.safeOrigin(contents.getURL(), '');
}
function persistHeaderGrades() {
  if (d.headerGradeSaveTimer) clearTimeout(d.headerGradeSaveTimer);
  d.headerGradeSaveTimer = setTimeout(() => {
    try {
      d.ledgerStore.writeJSONStore(d.headerGradeStorePath, { version: 1, hosts: d.headerGrades });
    } catch {}
  }, 400);
}
function listHeaderGrades(limit = 200) {
  d.loadHeaderGrades();
  const n = Math.max(1, Math.min(Number(limit) || 200, d.MAX_HEADER_GRADE_HOSTS));
  return d.headerGrades.slice(-n).reverse().map(h => ({ ...h, checks: h.checks.map(c => ({ ...c })) }));
}
function clearHeaderGrades() {
  d.loadHeaderGrades();
  d.headerGrades.length = 0;
  try { d.fsSync.unlinkSync(d.headerGradeStorePath); } catch {}
  persistHeaderGrades();
  return true;
}
function getHeaderGradeStats() {
  d.loadHeaderGrades();
  const byGrade = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  let insecure = 0;
  for (const h of d.headerGrades) {
    if (byGrade[h.grade] != null) byGrade[h.grade] += 1;
    if (h.insecureTransport) insecure += 1;
  }
  return { hosts: d.headerGrades.length, byGrade, insecureHosts: insecure };
}
function loadRequestLog() {
  if (d.requestLogLoaded) return;
  d.requestLogLoaded = true;
  try {
    const data = d.ledgerStore.readJSONStore(d.requestLogStorePath, {});
    if (data && Array.isArray(data.entries)) {
      d.requestLogStore = d.requestLog.hydrate(data.entries, d.MAX_REQUEST_LOG_HOSTS);
    }
  } catch {}
}
function persistRequestLog() {
  if (d.requestLogSaveTimer) clearTimeout(d.requestLogSaveTimer);
  d.requestLogSaveTimer = setTimeout(() => {
    try {
      const entries = d.requestLog.toList(d.requestLogStore);
      d.ledgerStore.writeJSONStore(d.requestLogStorePath, { version: 1, savedAt: Date.now(), entries });
    } catch {}
  }, 5000);
}
function listRequestLogEntries(limit = 200) {
  loadRequestLog();
  const n = Math.max(1, Math.min(Number(limit) || 200, d.MAX_REQUEST_LOG_HOSTS));
  return d.requestLog.toList(d.requestLogStore).slice(0, n);
}
function getRequestLogStats() {
  loadRequestLog();
  return d.requestLog.stats(d.requestLogStore);
}
function clearRequestLog() {
  loadRequestLog();
  d.requestLog.clear(d.requestLogStore);
  try { d.fsSync.unlinkSync(d.requestLogStorePath); } catch {}
  persistRequestLog();
  return true;
}
function persistBrandSpoofs() {
  if (d.brandSpoofSaveTimer) clearTimeout(d.brandSpoofSaveTimer);
  d.brandSpoofSaveTimer = setTimeout(() => {
    try {
      d.ledgerStore.writeJSONStore(d.brandSpoofStorePath, { version: 1, savedAt: Date.now(), hosts: d.brandSpoofs });
    } catch {}
  }, 5000);
}
function listBrandSpoofEntries(limit = 200) {
  d.loadBrandSpoofs();
  const n = Math.max(1, Math.min(Number(limit) || 200, d.MAX_BRAND_SPOOF_HOSTS));
  return d.brandSpoofs.slice(-n).reverse().map(h => ({ ...h }));
}
function getBrandSpoofStats() {
  d.loadBrandSpoofs();
  const byReason = {
    'typo-domain': 0,
    'brand-in-subdomain': 0,
    'brand-keyword-impersonation': 0,
    'url-structural': 0,
  };
  const brands = new Set();
  for (const h of d.brandSpoofs) {
    if (byReason[h.reason] === undefined) byReason[h.reason] = 0;
    byReason[h.reason] += 1;
    if (h.brand) brands.add(h.brand);
  }
  return { hosts: d.brandSpoofs.length, byReason, distinctBrands: brands.size };
}
function clearBrandSpoofs() {
  d.loadBrandSpoofs();
  d.brandSpoofs = [];
  try { d.fsSync.unlinkSync(d.brandSpoofStorePath); } catch {}
  persistBrandSpoofs();
  return true;
}
function loadClientCertChoices() {
  if (d.clientCertStoreLoaded) return;
  d.clientCertStoreLoaded = true;
  try {
    // 有界文本读：clientCert 台账缺失时 readBoundedText 返回 {missing}，不解析、不加载；
    // 被塞成巨值或损坏则交由外层 try/catch / loadJSON 容错，绝不整读撑爆主进程。
    const picked = d.ledgerStore.readBoundedText(d.clientCertStorePath);
    if (!picked.missing) d.clientCertStore.loadJSON(picked.text);
  } catch {}
}
function persistClientCertChoices() {
  if (d.clientCertSaveTimer) clearTimeout(d.clientCertSaveTimer);
  d.clientCertSaveTimer = setTimeout(() => {
    try {
      d.ledgerStore.writeJSONStore(d.clientCertStorePath, d.clientCertStore.toJSON());
    } catch {}
  }, 300);
}
function rejectAuthChallenge(nonce) {
  const c = d.pendingAuthChallenges.get(nonce);
  if (!c) return false;
  clearTimeout(c.timer);
  d.pendingAuthChallenges.delete(nonce);
  d.failAuthCallback(c.callback);
  return true;
}
function getClientCertChoiceStats() {
  const entries = d.clientCertStore.list();
  return { count: entries.length, max: d.netAuthGuard.MAX_REMEMBERED_CERT_HOSTS };
}
function setupNetworkStatus() {
  const report = () => {
    d.sendToRenderer('network-status-changed', { online: d.net.isOnline() });
  };
  d.app.on('online', report);
  d.app.on('offline', report);
  // 启动时先报一次当前状态
  setTimeout(report, 500);
}
function setupSystemEventGuards() {
  d.app.on('gpu-process-crashed', (_event, killed) => {
    try {
      const v = d.gpuAccessGuard.decideGPUCrash(d.gpuCrashState, { killed: !!killed }, Date.now());
      if (v.action !== d.gpuAccessGuard.ACTION_RECORD) return;
      d.recordSecurityEvent('gpu-process-crashed', 'warn', v.detail, '');
      try {
        d.sendToRenderer('gpu-process-gone', { reason: v.killed ? 'killed' : 'crashed' });
        if (d.mainWindow && !d.mainWindow.isDestroyed()) {
          d.sendToRenderer('show-toast',
            v.killed ? 'GPU 进程被系统终止，如画面异常请按 Ctrl+R 重载'
                     : 'GPU 进程崩溃已自动恢复，如画面异常请按 Ctrl+R 重载');
        }
      } catch {}
    } catch (err) {
      d.recordSecurityEvent('gpu-process-crashed', 'info',
        `GPU 崩溃守卫异常: ${String((err && err.message) || err)}`, '');
    }
  });

  d.app.on('gpu-info-update', () => {
    const now = Date.now();
    if (d.gpuInfoLastReport >= 0 && now - d.gpuInfoLastReport < d.GPU_INFO_REPORT_COOLDOWN_MS) return;
    // 用 basic 信息（含 auxAttributes），避免 'complete' 触发可能较慢的完整枚举。
    Promise.resolve()
      .then(() => (typeof d.app.getGPUInfo === 'function' ? d.app.getGPUInfo('basic') : null))
      .then((info) => {
        const clean = d.gpuAccessGuard.sanitizeGPUInfo(info && info.auxAttributes);
        if (clean.kept === 0) return;
        d.gpuInfoLastReport = Date.now();
        if (clean.fields.softwareRendering === true) {
          d.recordSecurityEvent('gpu-info-update', 'warn',
            'GPU 被重新枚举且当前回退到软件渲染（硬件加速可能不可用）', '');
        } else {
          d.recordSecurityEvent('gpu-info-update', 'info',
            'GPU 信息已更新（硬件加速生效）', '');
        }
      })
      .catch(() => {});
  });

  d.app.on('accessibility-support-changed', (_event, enabled) => {
    try {
      const v = d.gpuAccessGuard.decideAccessibilityChange(enabled);
      if (v.shouldRecord) {
        d.recordSecurityEvent('accessibility-changed', 'info', v.detail, '');
      }
    } catch {}
  });
}
function setupExtraSessionHardening() {
  return require('./sessionhardening').setupExtraSessionHardening(d.setupExtraSessionHardeningCtx, );
}
module.exports = { bindDeps, loadHttpsExceptions, persistHttpsExceptions, isHttpExceptionHost, loadUaPolicyStateFromDisk, persistUaPolicyState, persistRateLimitState, applyUaPolicyToSession, resolveEffectiveUa, applyRateLimitToItem, atomicWriteJSON, loadVaultStateFromDisk, persistVaultState, persistCleanAudit, persistVaultKey, maybeFallbackAfterUpgradeFailure, applyDarkMode, loadPnaLedger, persistPnaLedger, pnaLedgerStats, recordPnaBlock, loadFpLedger, persistFpLedger, applyWebRtcPolicy, loadDohLedger, persistDohLedger, dohStatus, applyWebRequestFiltering, originOfContents, persistHeaderGrades, listHeaderGrades, clearHeaderGrades, getHeaderGradeStats, loadRequestLog, persistRequestLog, listRequestLogEntries, getRequestLogStats, clearRequestLog, persistBrandSpoofs, listBrandSpoofEntries, getBrandSpoofStats, clearBrandSpoofs, loadClientCertChoices, persistClientCertChoices, rejectAuthChallenge, getClientCertChoiceStats, setupNetworkStatus, setupSystemEventGuards, setupExtraSessionHardening };
