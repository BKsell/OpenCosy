'use strict';
function registerSettingsPanels(d) {
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
}

module.exports = { registerSettingsPanels };
