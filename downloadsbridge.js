'use strict';

let d = {};

function bindDeps(next) {
  d = next;
}

function performDownloadOpen(resolved, opts) {
  const options = opts || {};
  if (!d.isInSafeDirs(resolved) || !d.fsSync.existsSync(resolved)) {
    return { ok: false, action: 'missing' };
  }
  const originUrl = d.downloadOriginByPath.has(resolved)
    ? d.downloadOriginByPath.get(resolved)
    : null;
  const baseName = d.path.basename(resolved);
  const target = d.dloadOpen.decideOpenTarget({ filePath: resolved, filename: baseName, hostUrl: originUrl });
  if (target.action === d.dloadOpen.ACTION.BLOCK) {
    d.recordSecurityEvent('download-open-blocked', 'warn',
      `打开下载项被文件名判定拦截: ${baseName}`, '');
    d.sendToRenderer('show-toast', '已阻止打开：文件名不安全');
    return { ok: false, action: 'block', reason: target.reason };
  }
  // 交给系统打开前再走一次路径消毒（控制字符 / UNC / 穿越）。可执行文件是否
  // 允许运行已由上面的来源确认决定，这里只挡畸形与越界路径。
  const launchReview = d.shellGuard.reviewLocalLaunchPath(resolved, true);
  if (!launchReview.ok) {
    d.recordSecurityEvent('download-blocked', 'warn',
      `打开本地文件被路径消毒拦截（${shellGuard.describeReason(launchReview.reason)}）`, '');
    d.sendToRenderer('show-toast', '已阻止打开：文件路径不安全');
    return { ok: false, action: 'block', reason: launchReview.reason };
  }
  // 本地网页 / 磁盘镜像这类“打开即获得本地来源或直接挂载”的类型只定位，
  // 用户需要时自己在浏览器 / 资源管理器里显式打开。
  if (target.action === d.dloadOpen.ACTION.REVEAL) {
    d.recordSecurityEvent('download-open-blocked', 'info',
      `下载项仅定位不执行: ${baseName}`, '');
    d.shell.showItemInFolder(resolved);
    return { ok: true, action: 'reveal' };
  }
  if (target.action === d.dloadOpen.ACTION.CONFIRM) {
    const host = originUrl ? d.urlResolve.safeHost(originUrl, originUrl) : '未知来源';
    if (d.mainWindow && !d.mainWindow.isDestroyed() && d.mainWindow.isMinimized()) d.mainWindow.restore();
    const advice = (target.reasons && target.reasons.length)
      ? target.reasons.join('\n')
      : '该文件是可执行程序或脚本，来自互联网（或来源不明），可能会危害您的计算机或更改系统设置。';
    const choice = d.dialog.showMessageBoxSync(d.mainWindow, {
      type: 'warning',
      buttons: ['取消', '仍然运行'],
      defaultId: 0,
      cancelId: 0,
      title: '安全提示：运行来自互联网的程序',
      message: `确定要打开 "${baseName}" 吗？`,
      detail: [
        `来源：${host}`,
        '',
        advice,
        '',
        '请仅在确认其来源可信时运行。',
      ].join('\n').replace(/\n{3,}/g, '\n\n'),
      noLink: true,
    });
    if (choice !== 1) {
      d.recordSecurityEvent('download-open-blocked', 'info',
        `用户取消运行来自互联网的文件: ${baseName}`, host);
      return { ok: false, action: 'cancel' };
    }
  }
  d.shell.openPath(resolved);
  return { ok: true, action: 'open' };
}

function confirmDownloadDecision(analysis, originUrl) {
  const host = d.urlResolve.safeHost(originUrl, originUrl || '未知来源');
  const lines = analysis.risks
    .filter(r => r.severity === d.dloadGuard.DECISION.CONFIRM)
    .map(r => `• ${r.message}`)
    .slice(0, 6);
  const detail = [
    `文件：${analysis.displayName}`,
    `来源：${host}`,
    '',
    ...lines,
    '',
    '此文件可能会运行程序、更改系统设置，或经过伪装诱导打开。请仅在确认来源可信时保存。',
  ].join('\n');
  const choice = d.dialog.showMessageBoxSync(d.mainWindow, {
    type: 'warning',
    buttons: ['取消下载', '仍然保存'],
    defaultId: 0,
    cancelId: 0,
    title: '安全提示：存在风险的下载',
    message: '该下载可能会损害您的计算机或经过类型伪装，是否仍要保存？',
    detail,
    noLink: true,
  });
  return choice === 1;
}

function getDownloadJournal() {
  if (d.downloadJournal) return d.downloadJournal;
  const downloadsRoot = d.app.getPath('downloads');
  d.downloadJournal = d.downloadJournalModule.createDownloadJournal({
    filePath: d.path.join(d.app.getPath('userData'), 'download-journal.json'),
    rootDir: downloadsRoot,
  });
  const loaded = d.downloadJournal.load();
  if (loaded.rejected.length > 0) {
    d.recordSecurityEvent('download-journal', 'warn',
      `下载台账载入时丢弃 ${loaded.rejected.length} 条非法记录`, 'download-journal');
  }
  const reconciled = d.downloadJournal.reconcile(d.downloadJournalFileProbe());
  if (!reconciled.ok) {
    d.recordSecurityEvent('download-journal', 'warn',
      `下载台账落盘文件核对结果未能保存: ${downloadJournalModule.describeJournalReject(reconciled.reason)}`,
      'download-journal');
  } else if (reconciled.changes.length > 0) {
    d.recordSecurityEvent('download-journal', 'info',
      `下载台账文件核对: ${downloadReconcileModule.summarizeReconcile(reconciled.summary)}`,
      'download-journal');
  }
  return d.downloadJournal;
}

function loadDownloadRisks() {
  if (d.downloadRiskLoaded) return;
  d.downloadRiskLoaded = true;
  try {
    const data = d.ledgerStore.readJSONStore(d.downloadRiskStorePath, {});
    const entries = Array.isArray(data && data.records) ? data.records : null;
    if (!entries) return;
    for (const r of entries) {
      if (!r || typeof r !== 'object') continue;
      if (typeof r.filename !== 'string' || !r.filename) continue;
      d.downloadRiskRecords.push({
        time: Number(r.time) || Date.now(),
        filename: String(r.filename).slice(0, 255),
        host: typeof r.host === 'string' ? String(r.host).slice(0, 255) : '',
        decision: ['allow', 'warn', 'confirm', 'reject'].includes(r.decision) ? r.decision : 'warn',
        action: ['saved', 'confirmed', 'cancelled', 'rejected'].includes(r.action) ? r.action : 'saved',
        ext: typeof r.ext === 'string' ? String(r.ext).slice(0, 32) : '',
        risks: Array.isArray(r.risks) ? r.risks.slice(0, 20).map(x => ({
          id: typeof x.id === 'string' ? x.id : 'unknown',
          severity: ['allow', 'warn', 'confirm', 'reject'].includes(x.severity) ? x.severity : 'warn',
          message: typeof x.message === 'string' ? x.message.slice(0, 300) : '',
        })) : [],
      });
      if (d.downloadRiskRecords.length >= d.MAX_DOWNLOAD_RISK_RECORDS) break;
    }
  } catch {}
}

function loadDownloads() {
  try {
    const p = d.downloadsStorePath();
    if (!d.fsSync.existsSync(p)) return;
    const parsed = d.ledgerStore.readJSONStore(p, null);
    if (!Array.isArray(parsed)) {
      d.recordSecurityEvent('downloads-load', 'warn', '下载台账文件结构非法，已忽略', '');
      return;
    }
    const clean = [];
    for (const raw of parsed.slice(0, d.MAX_PERSISTED_DOWNLOADS)) {
      const rec = d.downloadShelf.sanitizeDownloadRecord(raw, d.downloadShelf.ShelfLimits);
      if (rec && rec.id != null) clean.push(rec);
    }
    d.downloads.length = 0;
    d.downloads.push(...clean);
  } catch (e) {
    d.recordSecurityEvent('downloads-load', 'error',
      '下载台账读取失败: ' + String((e && e.message) || e).slice(0, 160), '');
  }
}

function journalDownloadState(downloadInfo, fallbackState) {
  if (!downloadInfo || !downloadInfo.id) return null;
  const state = downloadInfo.status === 'complete' ? d.downloadJournalModule.STATE.COMPLETE
    : downloadInfo.status === 'error' ? d.downloadJournalModule.STATE.ERROR
    : fallbackState || d.downloadJournalModule.STATE.DOWNLOADING;
  return {
    id: downloadInfo.id,
    url: downloadInfo.url || '',
    filename: downloadInfo.filename || '',
    host: downloadInfo.quotaHost || '',
    savePath: downloadInfo.savePath || '',
    partPath: downloadInfo.status === 'error' && downloadInfo.savePath ? `${downloadInfo.savePath}.crdownload` : '',
    totalBytes: Number.isFinite(downloadInfo.totalBytes) ? downloadInfo.totalBytes : 0,
    receivedBytes: Number.isFinite(downloadInfo.receivedBytes) ? downloadInfo.receivedBytes : 0,
    state,
    startedAt: downloadInfo.startTime || Date.now(),
  };
}

function downloadNotifyDeps() {
  return {
    isSupported: () => !!(Notification && Notification.isSupported && Notification.isSupported()),
    showNotification(note, onClick) {
      const n = new Notification({
        title: String((note && note.title) || ''),
        body: String((note && note.body) || ''),
        silent: !!(note && note.silent),
      });
      if (typeof onClick === 'function') n.on('click', onClick);
      n.show();
    },
    openPath(savePath) {
      if (!savePath) return;
      performDownloadOpen(d.path.resolve(String(savePath)), { notifySource: true });
    },
    focusWindow() {
      if (d.mainWindow && !d.mainWindow.isDestroyed()) {
        if (d.mainWindow.isMinimized()) d.mainWindow.restore();
        d.mainWindow.show();
        d.mainWindow.focus();
      }
    },
  };
}

module.exports = { performDownloadOpen, confirmDownloadDecision, getDownloadJournal, loadDownloadRisks, loadDownloads, journalDownloadState, downloadNotifyDeps, bindDeps };
