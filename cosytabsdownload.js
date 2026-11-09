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

function handleDownloadEvent(event, item, webContents) {
  return require('./downloadsevents').handleDownloadEvent(d.handleDownloadEventCtx, event, item, webContents);
}

function downloadJournalFileProbe() {
  return {
    exists: (target) => {
      try { return d.fsSync.lstatSync(target).isFile(); } catch { return false; }
    },
    sizeOf: (target) => {
      try {
        const stat = d.fsSync.lstatSync(target);
        return stat.isFile() ? stat.size : null;
      } catch { return null; }
    },
  };
}

function attachDownloadManager(sess) {
  if (!sess || d.managedDownloadSessions.has(sess)) return;
  try {
    sess.on('will-download', handleDownloadEvent);
    d.managedDownloadSessions.add(sess);
  } catch {}
}

function setupDownloadManager() {
  attachDownloadManager(d.session.defaultSession);
}

function formatSpeed(bytesPerSecond) {
  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
  let speed = bytesPerSecond;
  let unitIndex = 0;
  while (speed >= 1024 && unitIndex < units.length - 1) { speed /= 1024; unitIndex++; }
  return speed.toFixed(2) + ' ' + units[unitIndex];
}

function reviewToOpenUrl(review) {
  if (!review || !review.ok) return null;
  if (review.kind === 'local-html') {
    if (!d.fsSync.existsSync(review.value)) return null;
    return d.pathToFileURL(review.value).href;
  }
  return review.value; // web / internal 均已是规范化 href
}

function resolveStartupDeepLink(rawArg, source) {
  const review = d.deeplinkGuard.reviewStartupArg(rawArg);
  if (!review.ok) {
    d.recordSecurityEvent('deeplink-blocked', 'warn',
      `启动深链被拦截（来源:${source}，${d.deeplinkGuard.describeReason(review.reason)}）`, '');
    return null;
  }
  return reviewToOpenUrl(review);
}

function resolveStartupArgv(argv) {
  const review = d.deeplinkGuard.pickDeepLinkFromArgv(argv);
  return review ? reviewToOpenUrl(review) : null;
}

function applyFind(forward = true) {
  const wc = d.getCurrentTabWebContents();
  if (!wc || !d.findState.text) return;
  wc.findInPage(d.findState.text, {
    forward,
    matchCase: !!d.findState.matchCase,
    wholeWord: !!d.findState.wholeWord,
  });
}

function createContextMenu(menuType, selectedText = '') {
  const menu = new d.Menu();
  if (menuType === 'selection') {
    if (selectedText) {
      menu.append(new d.MenuItem({ label: '复制', click: () => { if (d.mainWindow?.webContents) d.mainWindow.webContents.copy(); } }));
      menu.append(new d.MenuItem({ type: 'separator' }));
    }
    menu.append(new d.MenuItem({ label: '主页', click: d.goHome }));
    menu.append(new d.MenuItem({ label: '设置', click: () => d.createNewTab('cosy://setting') }));
    menu.append(new d.MenuItem({ type: 'separator' }));
    if (d.isDev) menu.append(new d.MenuItem({ label: '开发者工具', click: d.toggleDevTools }));
  } else {
    if (d.isDev) menu.append(new d.MenuItem({ label: '开发者工具', click: d.toggleDevTools }));
    menu.append(new d.MenuItem({ label: '返回主页', click: d.goHome }));
    menu.append(new d.MenuItem({ label: '设置', click: () => d.createNewTab('cosy://setting') }));
  }
  return menu;
}

function sanitizeSettings(raw) {
  if (!raw || typeof raw !== 'object') return {};
  const clean = {};
  for (const [key, validate] of Object.entries(d.ALLOWED_SETTING_KEYS)) {
    if (key in raw && validate(raw[key])) clean[key] = raw[key];
  }
  return clean;
}

function sanitizeBookmarkLike(b) {
  return {
    url: typeof b.url === 'string' ? b.url.slice(0, 8192) : '',
    title: typeof b.title === 'string' ? b.title.slice(0, 300) : '',
    addedDate: typeof b.addedDate === 'string' ? b.addedDate : '',
  };
}

function openUrlFromInternalFrame(frameOk, url) {
  if (!frameOk) return { ok: false, error: 'denied' };
  const isInternal = typeof url === 'string' && url.startsWith('cosy://');
  if (!d.isSafeUrl(url) && !isInternal) return { ok: false, error: 'bad-url' };
  const tab = d.createNewTab(url);
  return { ok: true, id: tab.id, index: d.tabs.length - 1 };
}

function addToReadingList(url, title) {
  if (!d.isSafeUrl(url)) return { ok: false, error: 'bad-url' };
  let t = typeof title === 'string' ? title : '';
  t = t.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 300).trim();
  if (d.readingList.some(b => String(b.url || '') === url)) return { ok: true, added: false };
  d.readingList.push({ url, title: t || url, addedDate: new Date().toISOString() });
  d.saveReadingList();
  return { ok: true, added: true };
}

function customRulesSnapshot() {
  return {
    host: d.customRules.host.slice(),
    glob: d.customRules.glob.slice(),
    path: d.customRules.path.slice(),
    count: d.blockRules.ruleCount(d.customRules),
  };
}

function vaultPasswordOK(pw) {
  if (typeof pw !== 'string') return false;
  if (pw.length < 1 || pw.length > 256) return false;
  if (/[\x00-\x1f\x7f]/.test(pw)) return false;
  if (/^\s*$/.test(pw)) return false;
  try {
    return Buffer.byteLength(pw, 'utf8') <= 1024;
  } catch {
    return false;
  }
}

function originOfUrl(u) {
  return d.urlResolve.safeOrigin(u, '');
}

module.exports = { bindDeps, rehydrateTabGroups, sanitizeDownloadFilename, resolveUniqueDownloadPath, rememberDownloadOrigin, persistDownloadRisks, recordDownloadRisk, listDownloadRisks, clearDownloadRisks, analyzeDownloadSafety, handleDownloadEvent, downloadJournalFileProbe, attachDownloadManager, setupDownloadManager, formatSpeed, reviewToOpenUrl, resolveStartupDeepLink, resolveStartupArgv, applyFind, createContextMenu, sanitizeSettings, sanitizeBookmarkLike, openUrlFromInternalFrame, addToReadingList, customRulesSnapshot, vaultPasswordOK, originOfUrl };
