'use strict';

const { app, BrowserWindow, WebContentsView, ipcMain, session, protocol, Menu, MenuItem, dialog, shell, globalShortcut, clipboard, net, nativeTheme, webContents, safeStorage } = require('electron');
const dloadGuard = require('./dloadguard');
const downloadAdmission = require('./downloadadmission');
const downloadChain = require('./downloadchain');
const downloadChainLive = require('./downloadchainlive');
const downloadContentMagic = require('./downloadcontentmagic');
const downloadDiskSpace = require('./downloaddiskspace');
const downloadFinishGuard = require('./downloadfinishguard');
const downloadHostGuard = require('./downloadhostguard');
const downloadJournalModule = require('./downloadjournal');
const downloadName = require('./downloadname');
const downloadQuotaCore = require('./downloadquota');
const downloadRateGuard = require('./downloadratelimit');
const downloadSaveTarget = require('./downloadsavetarget');
const downloadSizeGuard = require('./downloadsizeguard');
const downloadSourceTrustGuard = require('./downloadsourcetrustguard');
const fsSync = require('fs');
const navigationTimeoutGuard = require('./navigationtimeoutguard');
const path = require('path');
const quarantine = require('./quarantine');

function handleDownloadEvent(ctx, event, item, webContents) {
  const {
    queueDownloadHashing,
    analyzeDownloadSafety,
    applyRateLimitToItem,
    confirmDownloadDecision,
    setCurrentDownloadInfo,
    downloadByteQuota,
    downloadDiskMonitor,
    downloadFreqLimiter,
    downloadMaxBytes: readDownloadMaxBytes,
    downloadSlotGuard,
    downloads: readDownloads,
    formatSpeed,
    getDownloadJournal,
    isSafeUrl,
    journalDownloadState,
    notifyDownloadResult,
    originOfContents,
    recordDownloadRisk,
    recordSecurityEvent,
    rememberDownloadOrigin,
    resolveUniqueDownloadPath,
    sanitizeDownloadFilename,
    sendShelf,
    sendToRenderer,
  } = ctx;
    const url = item.getURL();
    let mimeType = '';
    try { mimeType = typeof item.getMimeType === 'function' ? item.getMimeType() : ''; } catch { mimeType = ''; }

    const urlDecision = downloadHostGuard.evaluateDownloadUrl(url);
    const sourceTrust = downloadSourceTrustGuard.applyDownloadSourceTrustGuard({ url });
    if (!sourceTrust.allowed) {
      recordSecurityEvent('download-url', 'warn',
        `下载来源可信度: ${downloadSourceTrustGuard.describeFindings([{ reason: sourceTrust.reason }])}`,
        originOfContents(webContents));
    }
    const timeoutPlan = navigationTimeoutGuard.applyNavigationTimeoutGuard({ timeout: 30000, retries: 0 });
    if (urlDecision.action === downloadHostGuard.ACTION.BLOCK) {
      try { item.cancel(); } catch {}
      recordSecurityEvent('download-url', 'critical',
        `下载地址被拒绝: ${downloadHostGuard.describeDownloadUrl(urlDecision)}`,
        originOfContents(webContents));
      sendToRenderer('show-toast', `下载地址不安全，已取消：${downloadHostGuard.describeDownloadUrl(urlDecision)}`);
      return;
    }
    if (urlDecision.action === downloadHostGuard.ACTION.WARN) {
      recordSecurityEvent('download-url', 'warn',
        downloadHostGuard.describeDownloadUrl(urlDecision), originOfContents(webContents));
    }

    // 纯内核一次给出：URL 是否放行、净化后的文件名、危险类型档位与风险原因链。
    let rawFilename = item.getFilename();
    try {
      if (typeof item.getContentDisposition === 'function') {
        const cd = downloadName.parseContentDisposition(item.getContentDisposition());
        if (cd.filename) rawFilename = cd.filename;
      }
    } catch { rawFilename = item.getFilename(); }
    const admission = downloadAdmission.planDownloadAdmission(
      {
        isSafeUrl,
        sanitizeFilename: sanitizeDownloadFilename,
        analyzeName: analyzeDownloadSafety,
        DECISION: dloadGuard.DECISION,
      },
      { url, rawFilename, mimeType },
    );
    const riskAnalysis = admission.analysis || { decision: '', finalExt: '', risks: [] };
    const finalFilename = admission.finalFilename || 'download';
    const dlHost = admission.host;
    const declaredSize = downloadSizeGuard.decideDeclared(
      typeof item.getTotalBytes === 'function' ? item.getTotalBytes() : -1,
      readDownloadMaxBytes(),
    );
    if (declaredSize.action === downloadSizeGuard.ACTION.CANCEL) {
      try { item.cancel(); } catch {}
      const described = downloadSizeGuard.describe(declaredSize);
      recordSecurityEvent('download-size', 'critical', `下载体积超过上限已取消: ${described}`,
        originOfContents(webContents));
      recordDownloadRisk({
        filename: finalFilename, host: dlHost, decision: 'reject', action: 'rejected',
        ext: riskAnalysis.finalExt || '', reasons: [described],
      });
      sendToRenderer('show-toast', `下载体积超过上限，已取消：${described}`);
      sendShelf();
      return;
    }
    const chainCheck = downloadChain.analyzeDownloadChain(
      typeof item.getURLChain === 'function' ? item.getURLChain() : null,
    );
    if (chainCheck.verdict === downloadChain.VERDICT.BLOCK) {
      try { item.cancel(); } catch {}
      recordSecurityEvent('download-blocked', 'critical',
        `拒绝重定向链不安全的下载: ${downloadChain.describeDownloadChain(chainCheck)} -> ${url}`,
        originOfContents(webContents));
      recordDownloadRisk({
        filename: item.getFilename() || '(bad-chain)', host: chainCheck.finalHost || '',
        decision: 'reject', action: 'rejected', ext: '',
        risks: [chainCheck.reason],
      });
      sendToRenderer('show-toast', `已取消存在风险的重定向下载：${downloadChain.describeDownloadChain(chainCheck)}`);
      return;
    }
    const rateCheck = downloadFreqLimiter.record(chainCheck.finalHost || dlHost || '');
    if (!rateCheck.ok) {
      try { item.cancel(); } catch {}
      recordSecurityEvent('download-rate-limited', 'warn',
        `下载频率超限，已取消: ${downloadRateGuard.describeDownloadRateLimit(rateCheck)} -> ${url}`,
        originOfContents(webContents));
      recordDownloadRisk({
        filename: item.getFilename() || '(rate-limited)', host: rateCheck.host || '',
        decision: 'reject', action: 'rejected', ext: '',
        risks: [rateCheck.reason],
      });
      sendToRenderer('show-toast', `下载过于频繁，已取消：${downloadRateGuard.describeDownloadRateLimit(rateCheck)}`);
      return;
    }

    // block-unsafe-url：不安全协议/地址（file:/javascript:/data: 等）直接取消整次下载。
    if (admission.action === downloadAdmission.ACTION_BLOCK_UNSAFE) {
      recordSecurityEvent('download-blocked', 'critical',
        `阻止了来自不安全协议/地址的下载: ${url}`, originOfContents(webContents));
      // 与 reject 分支保持一致：危险协议下载拦截也要进 download-risk 台账，
      // 否则 cosy://security 安全中心只能看到危险文件名、看不到危险协议来源。
      recordDownloadRisk({
        filename: item.getFilename() || '(unsafe-url)', host: dlHost,
        decision: 'reject', action: 'rejected',
        ext: riskAnalysis.finalExt || '', risks: riskAnalysis.risks || [],
      });
      event.preventDefault();
      return;
    }

    // reject：文件名无法净化成合法名字，直接取消。
    if (admission.action === downloadAdmission.ACTION_REJECT) {
      try { item.cancel(); } catch {}
      recordSecurityEvent('download-blocked', 'critical',
        `拒绝保存文件名非法的下载: ${item.getFilename()}`, originOfContents(webContents));
      recordDownloadRisk({
        filename: item.getFilename(), host: dlHost, decision: 'reject', action: 'rejected',
        ext: riskAnalysis.finalExt, risks: riskAnalysis.risks,
      });
      sendToRenderer('show-toast', '下载文件名非法，已取消');
      return;
    }

    // confirm：可执行 / 伪装 / MIME 不符必须用户显式确认，阻断静默 drive-by 下载。
    if (admission.action === downloadAdmission.ACTION_CONFIRM) {
      const allow = confirmDownloadDecision(riskAnalysis, url);
      if (!allow) {
        try { item.cancel(); } catch {}
        recordSecurityEvent('download-rejected', 'warn',
          `用户取消了存在风险的下载: ${finalFilename}`, originOfContents(webContents));
        recordDownloadRisk({
          filename: finalFilename, host: dlHost, decision: 'confirm', action: 'cancelled',
          ext: riskAnalysis.finalExt, risks: riskAnalysis.risks,
        });
        sendToRenderer('show-toast', `已取消存在风险的下载：${finalFilename}`);
        return;
      }
      recordSecurityEvent('download-confirmed', 'info',
        `用户确认保存存在风险的下载: ${finalFilename}`, originOfContents(webContents));
    }

    // warn：容器（内部文件不继承 MOTW）/ 本地 HTML 等，保存并轻提示。
    // 走到这里 action 必为 WARN（CONFIRM 已在上方独立分支处理），台账动作即 saved。
    if (admission.action === downloadAdmission.ACTION_WARN) {
      recordDownloadRisk({
        filename: finalFilename, host: dlHost, decision: 'warn', action: 'saved',
        ext: riskAnalysis.finalExt, risks: riskAnalysis.risks,
      });
    }

    const totalBytes = item.getTotalBytes();
    let downloadInfo = readDownloads().find(d => d.url === url && d.item === null && d.isItemValid === false);
    if (downloadInfo) {
      downloadInfo.item = item;
      downloadInfo.filename = finalFilename;
      downloadInfo.totalBytes = totalBytes;
      downloadInfo.isItemValid = true;
      downloadInfo.status = 'downloading';
    } else {
      // 全新下载：不再 preventDefault + 新开下载页等用户确认，
      // 直接按现代浏览器行为自动保存到下载目录，由底部 shelf 展示进度。
      downloadInfo = {
        id: Date.now().toString(), url, filename: finalFilename, totalBytes,
        receivedBytes: 0, progress: 0, speed: '0 B/s', status: 'downloading',
        startTime: Date.now(), savePath: null, item,
        lastUpdate: Date.now(), lastReceivedBytes: 0, isItemValid: true,
        expectedHash: null
      };
      readDownloads().push(downloadInfo);
    }
    setCurrentDownloadInfo(downloadInfo);
    const downloadRoot = app.getPath('downloads');
    let diskFreeBytes = null;
    try {
      const diskStat = fsSync.statfsSync(downloadRoot);
      diskFreeBytes = Number(diskStat.bavail) * Number(diskStat.bsize);
    } catch (diskProbeError) {
      diskFreeBytes = null;
    }
    let existingDownloadBytes = 0;
    if (downloadInfo.savePath) {
      try {
        existingDownloadBytes = Number(fsSync.statSync(downloadInfo.savePath).size) || 0;
      } catch (existingProbeError) {
        existingDownloadBytes = 0;
      }
    }
    downloadInfo.diskFreeBytes = diskFreeBytes;
    const diskDecision = diskFreeBytes === null
      ? {
        action: downloadDiskSpace.ACTION.WARN, reason: downloadDiskSpace.REASON.UNKNOWN_SIZE,
        freeBytes: null, requiredFreeBytes: 0, shortfallBytes: 0,
      }
      : downloadDiskSpace.evaluateSpace({ freeBytes: diskFreeBytes, totalBytes, existingBytes: existingDownloadBytes });
    if (diskDecision.action === downloadDiskSpace.ACTION.BLOCK) {
      try { item.cancel(); } catch {}
      downloadInfo.status = 'error';
      recordSecurityEvent('download-blocked', 'critical',
        `磁盘空间不足，拒绝下载: ${downloadDiskSpace.describeDecision(diskDecision)}`,
        originOfContents(webContents));
      sendToRenderer('show-toast', `空间不足，已取消下载：${downloadDiskSpace.describeDecision(diskDecision)}`);
      sendShelf();
      return;
    }
    if (diskDecision.action === downloadDiskSpace.ACTION.WARN) {
      recordSecurityEvent('download-disk', 'warn',
        downloadDiskSpace.describeDecision(diskDecision), originOfContents(webContents));
    }
    if (downloadInfo.savePath) {
      const reusedCheck = downloadSaveTarget.auditSaveTargetReal(
        downloadRoot, downloadInfo.savePath, path.basename(downloadInfo.savePath),
      );
      if (!reusedCheck.ok) {
        downloadInfo.savePath = null;
        recordSecurityEvent('download-savepath', 'warn',
          `复用下载槽位的保存路径未通过校验: ${downloadSaveTarget.describeSaveTargetReject(reusedCheck.reason)}`,
          originOfContents(webContents));
      }
    }
    const reserveSlotFor = (candidatePath, attempt) => {
      let target = candidatePath;
      if (attempt > 0) {
        const parsed = path.parse(candidatePath);
        target = path.join(parsed.dir, `${parsed.name} (${attempt})${parsed.ext}`);
      }
      const reservation = downloadSlotGuard.reserve({ id: downloadInfo.id, path: target });
      return reservation.ok ? target : '';
    };
    if (downloadInfo.savePath) {
      if (reserveSlotFor(downloadInfo.savePath, 0)) {
        item.setSavePath(downloadInfo.savePath);
      } else {
        recordSecurityEvent('download-savepath', 'warn',
          `复用下载槽位的目标已被其他下载占用，重新分配文件名: ${path.basename(downloadInfo.savePath)}`,
          originOfContents(webContents));
        downloadInfo.savePath = null;
      }
    }
    if (downloadInfo.savePath) {
      item.setSavePath(downloadInfo.savePath);
    } else {
      let reservedTarget = '';
      for (let attempt = 0; attempt < 4 && !reservedTarget; attempt += 1) {
        const candidate = resolveUniqueDownloadPath(downloadRoot, finalFilename);
        const saveCheck = downloadSaveTarget.auditSaveTargetReal(downloadRoot, candidate, path.basename(candidate));
        if (!saveCheck.ok) {
          try { item.cancel(); } catch {}
          recordSecurityEvent('download-blocked', 'critical',
            `拒绝保存到非法路径的下载: ${downloadSaveTarget.describeSaveTargetReject(saveCheck.reason)}`,
            originOfContents(webContents));
          recordDownloadRisk({
            filename: finalFilename, host: dlHost, decision: 'reject', action: 'rejected',
            ext: riskAnalysis.finalExt, risks: riskAnalysis.risks,
          });
          sendToRenderer('show-toast', `下载保存路径非法，已取消：${downloadSaveTarget.describeSaveTargetReject(saveCheck.reason)}`);
          return;
        }
        reservedTarget = reserveSlotFor(saveCheck.path, attempt);
      }
      if (!reservedTarget) {
        try { item.cancel(); } catch {}
        recordSecurityEvent('download-blocked', 'critical',
          '下载保存槽位持续冲突，无法分配唯一文件名', originOfContents(webContents));
        sendToRenderer('show-toast', '同名文件正在下载，已取消本次下载');
        return;
      }
      item.setSavePath(reservedTarget);
      downloadInfo.savePath = reservedTarget;
    }
    const journalStart = journalDownloadState(downloadInfo, downloadJournalModule.STATE.STARTED);
    if (journalStart) {
      const journalResult = getDownloadJournal().record(journalStart);
      if (!journalResult.ok) {
        recordSecurityEvent('download-journal', 'warn',
          `下载台账写入被拒绝: ${downloadJournalModule.describeJournalReject(journalResult.reason)}`,
          originOfContents(webContents));
      }
    }
    downloadInfo.quotaHost = chainCheck.finalHost || dlHost || 'unknown-host';
    downloadInfo.quotaReserved = 0;
    const quotaDeclared = Number.isFinite(totalBytes) && totalBytes > 0 ? totalBytes : 0;
    const quotaCheck = downloadByteQuota.reserve(downloadInfo.quotaHost, quotaDeclared);
    if (!quotaCheck.ok) {
      try { item.cancel(); } catch {}
      recordSecurityEvent('download-quota', 'warn',
        `下载字节配额拒绝: ${downloadQuotaCore.describeQuotaReject(quotaCheck.reason, downloadInfo.quotaHost)}`,
        originOfContents(webContents));
      recordDownloadRisk({
        filename: finalFilename, host: downloadInfo.quotaHost, decision: 'reject', action: 'rejected',
        ext: riskAnalysis.finalExt, risks: riskAnalysis.risks,
      });
      sendToRenderer('show-toast', `下载超出字节配额，已取消：${downloadQuotaCore.describeQuotaReject(quotaCheck.reason, downloadInfo.quotaHost)}`);
      return;
    }
    downloadInfo.quotaHost = quotaCheck.host;
    downloadInfo.quotaReserved = quotaCheck.reservedBytes;
    applyRateLimitToItem(item);
    sendShelf();
    sendToRenderer('download-status-changed', { id: downloadInfo.id, status: 'downloading' });
    item.on('updated', (event, state) => {
      if (state === 'progressing') {
        const liveCheck = downloadChainLive.auditLiveChain(
          typeof item.getURLChain === 'function' ? item.getURLChain() : null,
        );
        if (liveCheck.verdict === downloadChainLive.VERDICT.ABORT) {
          try { item.cancel(); } catch {}
          downloadInfo.status = 'error';
          recordSecurityEvent('download-blocked', 'critical',
            `下载过程中重定向链失效: ${downloadChainLive.describeLiveChain(liveCheck)}`,
            originOfContents(webContents));
          sendToRenderer('show-toast', `已取消重定向链失效的下载：${downloadChainLive.describeLiveChain(liveCheck)}`);
          sendShelf();
          return;
        }
        const receivedBytes = item.getReceivedBytes();
        const totalBytes = item.getTotalBytes();
        const sizeDecision = downloadSizeGuard.decideProgress(receivedBytes, readDownloadMaxBytes());
        if (sizeDecision.action === downloadSizeGuard.ACTION.CANCEL) {
          try { item.cancel(); } catch {}
          downloadInfo.status = 'error';
          downloadInfo.receivedBytes = receivedBytes;
          if (Number.isFinite(totalBytes) && totalBytes > 0) downloadInfo.totalBytes = totalBytes;
          const described = downloadSizeGuard.describe(sizeDecision);
          recordSecurityEvent('download-size', 'critical', `下载体积超过上限已中断: ${described}`,
            originOfContents(webContents));
          sendToRenderer('download-status-changed', { id: downloadInfo.id, status: 'error' });
          sendToRenderer('show-toast', `下载体积超过上限，已中断：${described}`);
          sendShelf();
          return;
        }
        const quotaDelta = receivedBytes - (downloadInfo.quotaReserved || 0);
        if (quotaDelta > 0) {
          const topUp = downloadByteQuota.reserve(downloadInfo.quotaHost || '', quotaDelta);
          if (!topUp.ok) {
            try { item.cancel(); } catch {}
            downloadInfo.status = 'error';
            const described = downloadQuotaCore.describeQuotaReject(topUp.reason, downloadInfo.quotaHost);
            recordSecurityEvent('download-quota', 'warn', `下载字节配额拒绝: ${described}`,
              originOfContents(webContents));
            recordDownloadRisk({
              filename: downloadInfo.filename || '(quota-exceeded)', host: downloadInfo.quotaHost || '',
              decision: 'reject', action: 'rejected', ext: '', risks: [topUp.reason],
            });
            sendToRenderer('download-status-changed', { id: downloadInfo.id, status: 'error' });
            sendToRenderer('show-toast', `下载超出字节配额，已取消：${described}`);
            sendShelf();
            return;
          }
          downloadInfo.quotaReserved = (downloadInfo.quotaReserved || 0) + quotaDelta;
        }
        let liveFreeBytes = downloadInfo.diskFreeBytes;
        try {
          const liveStat = fsSync.statfsSync(downloadRoot);
          liveFreeBytes = Number(liveStat.bavail) * Number(liveStat.bsize);
        } catch (liveProbeError) {
          liveFreeBytes = downloadInfo.diskFreeBytes;
        }
        const diskEvent = downloadDiskMonitor.sample({
          id: downloadInfo.id, freeBytes: liveFreeBytes, totalBytes, receivedBytes,
        });
        if (diskEvent.action === downloadDiskMonitor.ACTION.PAUSE) {
          try { item.pause(); } catch {}
          downloadInfo.status = 'paused';
          recordSecurityEvent('download-paused', 'warn',
            `磁盘剩余空间不足，下载暂停: ${downloadDiskSpace.describeDecision(diskEvent.decision)}`,
            originOfContents(webContents));
          if (downloadDiskMonitor.shouldNotify(downloadInfo.id)) {
            downloadDiskMonitor.markNotified(downloadInfo.id);
            sendToRenderer('show-toast', `磁盘空间不足，下载已暂停：${downloadInfo.filename}`);
          }
          sendShelf();
          return;
        }
        if (diskEvent.action === downloadDiskMonitor.ACTION.RESUME) {
          try { item.resume(); } catch {}
          downloadInfo.status = 'downloading';
          recordSecurityEvent('download-resumed', 'info',
            '磁盘空间恢复，下载继续', originOfContents(webContents));
          sendToRenderer('show-toast', `磁盘空间恢复，继续下载：${downloadInfo.filename}`);
        }
        const progress = totalBytes > 0 ? ((receivedBytes / totalBytes) * 100).toFixed(2) : 0;
        const now = Date.now();
        const timeDiff = (now - downloadInfo.lastUpdate) / 1000;
        if (timeDiff > 0) {
          const bytesDiff = receivedBytes - downloadInfo.lastReceivedBytes;
          downloadInfo.speed = formatSpeed(bytesDiff / timeDiff);
        }
        downloadInfo.receivedBytes = receivedBytes;
        downloadInfo.progress = progress;
        downloadInfo.lastUpdate = now;
        downloadInfo.lastReceivedBytes = receivedBytes;
        downloadInfo.status = 'downloading';
        sendToRenderer('download-progress', { id: downloadInfo.id, receivedBytes, totalBytes, progress, speed: downloadInfo.speed });
        sendShelf();
      }
    });
    item.on('done', (event, state) => {
      downloadInfo.isItemValid = false;
      downloadDiskMonitor.release(downloadInfo.id);
      downloadSlotGuard.release(downloadInfo.id);
      if (state === 'completed') {
        const quotaSettled = downloadByteQuota.settle(
          downloadInfo.quotaHost || '',
          downloadInfo.quotaReserved || 0,
          Math.max(downloadInfo.quotaReserved || 0, downloadInfo.receivedBytes || 0),
        );
        if (!quotaSettled) {
          recordSecurityEvent('download-quota', 'warn',
            `下载完成后实际字节超出配额预算，预留已回滚: ${downloadInfo.quotaHost || ''}`, 'download-manager');
        }
      } else {
        downloadByteQuota.release(downloadInfo.quotaHost || '', downloadInfo.quotaReserved || 0);
      }
      if (state === 'completed') {
        downloadInfo.savePath = item.getSavePath();
        let finishStat = null;
        try { finishStat = fsSync.lstatSync(downloadInfo.savePath); } catch { finishStat = null; }
        if (finishStat) {
          const finishAudit = downloadFinishGuard.auditDownloadResult({
            rootDir: downloadRoot,
            savePath: downloadInfo.savePath,
            expectedBytes: downloadInfo.totalBytes,
            actualBytes: finishStat.size,
            isSymlink: finishStat.isSymbolicLink(),
            isRegular: finishStat.isFile(),
          });
          if (finishAudit.action === downloadFinishGuard.ACTION.BLOCK) {
            downloadInfo.status = 'error';
            recordSecurityEvent('download-finish', 'critical',
              `下载落盘校验失败: ${downloadFinishGuard.describeDownloadAudit(finishAudit)}`,
              originOfContents(webContents));
            sendToRenderer('download-error', {
              id: downloadInfo.id,
              filename: downloadInfo.filename || finalFilename,
              errorMessage: '下载文件未通过落盘校验，已标记为失败',
            });
            sendShelf();
            return;
          }
          if (finishAudit.action === downloadFinishGuard.ACTION.WARN) {
            recordSecurityEvent('download-finish', 'warn',
              downloadFinishGuard.describeDownloadAudit(finishAudit), originOfContents(webContents));
          }
          const magicProbe = downloadContentMagic.readMagic(downloadInfo.savePath);
          if (magicProbe.ok) {
            const contentAudit = downloadContentMagic.auditDownloadedContent({
              name: path.basename(downloadInfo.savePath),
              mime: mimeType,
              magic: magicProbe.magic,
            });
            if (contentAudit.action === downloadContentMagic.ACTION.BLOCK) {
              downloadInfo.status = 'error';
              recordSecurityEvent('download-content', 'critical',
                `下载内容伪装检测命中: ${downloadContentMagic.describeContentAudit(contentAudit)}`,
                originOfContents(webContents));
              sendToRenderer('download-error', {
                id: downloadInfo.id,
                filename: downloadInfo.filename || finalFilename,
                errorMessage: '下载内容与扩展名不符，已标记为可疑',
              });
              sendShelf();
              return;
            }
            if (contentAudit.action === downloadContentMagic.ACTION.WARN) {
              recordSecurityEvent('download-content', 'warn',
                downloadContentMagic.describeContentAudit(contentAudit), originOfContents(webContents));
            }
          }
        }
        downloadInfo.status = 'complete';
        sendToRenderer('download-complete', { id: downloadInfo.id, savePath: downloadInfo.savePath });
        // 系统通知：完成（静音、低打扰；点击打开文件）。在 MOTW 补写之前弹，
        // 用户看到通知时文件已落盘且来源登记已完成。
        notifyDownloadResult('complete', {
          filename: downloadInfo.filename || finalFilename,
          sizeBytes: downloadInfo.totalBytes,
          url: downloadInfo.url || url,
          savePath: downloadInfo.savePath,
        });
        // 登记来源，供“打开文件”时判断互联网可执行文件是否需要二次确认。
        const completedUrl = downloadInfo.url || url;
        rememberDownloadOrigin(downloadInfo.savePath, completedUrl);
        // 下载完成后排进串行摘要队列，异步算 SHA-256 并登记到 cosy://hashes；
        // 用净化后的文件名与来源 URL，不落完整本地路径。
        queueDownloadHashing({
          id: downloadInfo.id,
          savePath: downloadInfo.savePath,
          url: completedUrl,
          filename: downloadInfo.filename || finalFilename,
        });
        // 显式补写 Windows Mark-of-the-Web（Zone.Identifier ADS）。Chromium
        // 自定义落盘/跨盘移动/从压缩包解出都可能丢失 MOTW；best-effort，失败
        // （非 NTFS/权限）只审计，不影响已完成的下载。
        try {
          const motw = quarantine.applyMarkOfTheWeb(
            { platform: process.platform, appendFileSync: fsSync.appendFileSync },
            downloadInfo.savePath,
            { hostUrl: completedUrl, lastWriteTime: new Date().toISOString() }
          );
          if (motw.wrote === false && motw.reason !== 'not-internet' &&
              motw.reason !== 'unsupported-platform') {
            recordSecurityEvent('download-motw', 'info',
              `MOTW 标记未写入 (${motw.reason}): ${downloadInfo.filename || ''}`,
              originOfContents(webContents));
          }
        } catch (motwErr) {
          recordSecurityEvent('download-motw', 'info',
            `MOTW 标记异常: ${String(motwErr && motwErr.message || motwErr)}`,
            originOfContents(webContents));
        }
      } else {
        downloadInfo.status = 'error';
        const failureReason = state === 'interrupted' ? '下载被中断' : '下载未能完成';
        sendToRenderer('download-error', {
          id: downloadInfo.id,
          filename: downloadInfo.filename || finalFilename,
          errorMessage: failureReason,
        });
        // 系统通知：失败（非静音，高打扰；点击只聚焦窗口，不自动重试）。
        notifyDownloadResult('error', {
          filename: downloadInfo.filename || finalFilename,
          errorMessage: failureReason,
        });
      }
      const journalDone = journalDownloadState(downloadInfo);
      if (journalDone) {
        const journalResult = getDownloadJournal().update(downloadInfo.id, {
          state: journalDone.state,
          receivedBytes: journalDone.receivedBytes,
          savePath: journalDone.savePath,
          partPath: journalDone.partPath,
        });
        if (!journalResult.ok) {
          recordSecurityEvent('download-journal', 'warn',
            `下载台账收尾写入被拒绝: ${downloadJournalModule.describeJournalReject(journalResult.reason)}`,
            originOfContents(webContents));
        }
      }
      sendShelf();
    });
}

module.exports = { handleDownloadEvent };
