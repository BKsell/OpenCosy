'use strict';

let d = {};

function bindDeps(x) {
  d = x;
}

function rehydrateTabGroups() {
  const stored = d.loadStoredTabGroups();
  if (!stored.length) return 0;
  const current = d.tabs.map(t => ({ id: t.id, pinned: !!t.pinned }));
  const clean = d.tabGroups.rehydrateGroupsByTabs(stored, current);
  d.tabGroupModel.loadStored(clean);
  if (d.tabGroupModel.groupCount() > 0) {
    d.applyTabGroupArrangement();
    d.broadcastTabGroups();
  }
  return d.tabGroupModel.groupCount();
}

function sanitizeDownloadFilename(name) {
  if (!name || typeof name !== 'string') return 'download';
  const res = d.dloadGuard.sanitizeName(name);
  if (res.rejected || !res.name) return 'download';
  // 双保险：dloadguard 已剥目录，这里再清一遍 Windows/Unix 保留字符。
  const final = d.downloadName.sanitizeDownloadName(res.name, 'download');
  if (final.changed) {
    d.recordSecurityEvent('download-name', 'info',
      `下载文件名已净化（${final.reasons.join(',')}）`, '');
  }
  return final.name || 'download';
}

function resolveUniqueDownloadPath(dir, filename) {
  let existingNames = [];
  try {
    existingNames = d.fsSync.readdirSync(dir);
  } catch (scanError) {
    existingNames = [];
  }
  const allocation = d.downloadPathCollision.claimUniquePath({ dir, filename, taken: existingNames });
  if (!allocation.ok) {
    d.recordSecurityEvent('download-savepath', 'critical',
      `无法分配唯一下载文件名: ${d.downloadPathCollision.describeAllocation(allocation)}`, 'download-manager');
    return '';
  }
  return allocation.path;
}

function rememberDownloadOrigin(savePath, originUrl) {
  if (!savePath || !originUrl) return;
  if (d.downloadOriginByPath.size >= d.MAX_DOWNLOAD_ORIGIN_ENTRIES) {
    const oldest = d.downloadOriginByPath.keys().next().value;
    d.downloadOriginByPath.delete(oldest);
  }
  d.downloadOriginByPath.set(savePath, originUrl);
}

function persistDownloadRisks() {
  if (d.downloadRiskSaveTimer) clearTimeout(d.downloadRiskSaveTimer);
  d.downloadRiskSaveTimer = setTimeout(() => {
    try {
      d.ledgerStore.writeJSONStore(d.downloadRiskStorePath, { version: 1, records: d.downloadRiskRecords });
    } catch {}
  }, 300);
}

function recordDownloadRisk(entry) {
  d.loadDownloadRisks();
  d.downloadRiskRecords.push({
    time: Date.now(),
    filename: String(entry.filename || '').slice(0, 255),
    host: String(entry.host || '').slice(0, 255),
    decision: entry.decision || 'warn',
    action: entry.action || 'saved',
    ext: String(entry.ext || '').slice(0, 32),
    risks: Array.isArray(entry.risks) ? entry.risks.slice(0, 20) : [],
  });
  if (d.downloadRiskRecords.length > d.MAX_DOWNLOAD_RISK_RECORDS) {
    d.downloadRiskRecords.splice(0, d.downloadRiskRecords.length - d.MAX_DOWNLOAD_RISK_RECORDS);
  }
  persistDownloadRisks();
}

function listDownloadRisks(limit) {
  d.loadDownloadRisks();
  const max = Math.max(1, Math.min(500, Number(limit) || 200));
  return d.downloadRiskRecords.slice(-max).reverse().map(r => ({ ...r, risks: r.risks || [] }));
}

function clearDownloadRisks() {
  d.loadDownloadRisks();
  const n = d.downloadRiskRecords.length;
  d.downloadRiskRecords.length = 0;
  persistDownloadRisks();
  return n;
}

function analyzeDownloadSafety(filename, mime) {
  return d.dloadGuard.analyzeDownloadName(filename, mime);
}

const cosytabsurfaces = require('./cosytabsurfaces_core');

function bindDepsAll(x) {
  d = x;
  cosytabsurfaces.bindDeps(x);
}

module.exports = Object.assign({ bindDeps: bindDepsAll }, cosytabsurfaces, { bindDeps, rehydrateTabGroups, sanitizeDownloadFilename, resolveUniqueDownloadPath, rememberDownloadOrigin, persistDownloadRisks, recordDownloadRisk, listDownloadRisks, clearDownloadRisks, analyzeDownloadSafety });
