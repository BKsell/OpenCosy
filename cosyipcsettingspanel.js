'use strict';

const { registerVaultIpc } = require('./cosyipcvaultipc');

function registerSettingsPanels(d) {
registerVaultIpc(d);
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
    d.ledgerStore.writeJSONStore(settingsPath, d.sanitizeSettings(Object.assign({}, cur, { downloadMaxBytes: d.downloadMaxBytes })), { pretty: true });
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
