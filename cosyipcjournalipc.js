'use strict';

function registerDownloadJournalIpc(d) {
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
  for (const rec of d.downloads) {
    if (rec.item && rec.isItemValid) d.applyRateLimitToItem(rec.item);
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
}

module.exports = { registerDownloadJournalIpc };
