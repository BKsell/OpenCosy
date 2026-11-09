'use strict';

function create(ctx) {
  const {
    ALLOWED_PERMISSIONS, clearBrandSpoofs, clearCspReports, clearDownloadRisks, clearHeaderGrades, clearRequestLog,
    clearSecurityEvents, clipboard, clipboardFrame, clipboardReadOrigin, confirmAndOpenExternal, createDenyLedger,
    dialog, displayGuard, fullscreenFrame, getBrandSpoofStats, getCspReportStats, getCurrentTabWebContents,
    getHeaderGradeStats, getRequestLogStats, ipcMain, isMainSender, listBrandSpoofEntries, listCspReports,
    listDownloadRisks, listHeaderGrades, listRequestLogEntries, listSecurityEvents, notificationFrame, pointerLockFrame,
    popupOpenerFrame, recordCspViolationFromRenderer, recordSecurityEvent, removeCspReport, sendToRenderer, session,
    urlClean, urlResolve, webContents,
  } = ctx;
  const readCurrentTabIndex = ctx.readCurrentTabIndex;
  const readMainWindow = ctx.readMainWindow;
  const readTabs = ctx.readTabs;

  // 敏感权限不能再静默放行：旧实现里 media/geolocation/notifications/midi 全部
  // callback(true)，任意网站都能不经询问打开摄像头、麦克风、定位、通知。
  // 这些改为向当前标签的渲染层发请求，由页面内询问条决定，默认安全失败。
  const SENSITIVE_PAGE_PERMISSIONS = new Set([
    'media', 'geolocation', 'notifications', 'midi', 'midiSysex',
    // 读剪贴板能拿到密码 / 验证码 / 钱包地址等敏感内容，绝不静默放行，
    // 必须像摄像头定位那样弹询问条由用户显式授权。
    'clipboard-read',
  ]);
  // requestId -> settle(granted)，只允许决一次，超时 / 页面销毁默认拒绝。
  const pendingPermissionRequests = new Map();
  let permissionSeq = 0;
  const permissionDecisionTimeoutMs = 60000;

  const tabIdForContents = (wc) => {
    const tab = readTabs().find(t => t.view && t.view.webContents === wc);
    return tab ? tab.id : null;
  };

  const frameGuardedPermissions = new Set(['pointerLock', 'fullscreen', 'clipboard-sanitized-write', 'pop-up', 'notifications']);
  const permDenyLedger = createDenyLedger({ windowMs: 60000, maxPerKey: 3, maxKeys: 512 });

  const permissionFrameInput = (wc, details, fallbackOrigin) => {
    const activeTab = readTabs()[readCurrentTabIndex()];
    const tab = readTabs().find(t => t.view && t.view.webContents === wc);
    const requested = (details && details.requestingUrl) || fallbackOrigin || wc.getURL();
    return {
      requestUrl: requested,
      topUrl: wc.getURL(),
      isMainFrame: !(details && details.isMainFrame === false),
      tabActive: !tab || !activeTab ? true : tab.id === activeTab.id,
      windowFocused: readMainWindow() && typeof readMainWindow().isFocused === 'function' ? readMainWindow().isFocused() : true,
    };
  };

  const evaluatePermissionFrame = (wc, permission, details, fallbackOrigin) => {
    const input = permissionFrameInput(wc, details, fallbackOrigin);
    if (permission === 'pointerLock') return pointerLockFrame.evaluatePointerLockFrame(input);
    if (permission === 'fullscreen') return fullscreenFrame.evaluateFullscreenFrame(input);
    if (permission === 'pop-up') return popupOpenerFrame.evaluatePopupFrame(input);
    if (permission === 'notifications') return notificationFrame.evaluateNotificationFrame(input);
    return clipboardFrame.evaluateClipboardFrame(input);
  };

  const notePermissionDeny = (origin, permission, detail) => {
    const entry = permDenyLedger.record({ origin, permission });
    if (entry.log) {
      recordSecurityEvent('permission-blocked', 'warn', detail, origin);
    }
    return entry;
  };

  const enforceFrameGuard = (wc, permission, details, fallbackOrigin) => {
    if (!frameGuardedPermissions.has(permission)) return true;
    if (!wc || (typeof wc.isDestroyed === 'function' && wc.isDestroyed())) return true;
    const origin = urlResolve.safeOrigin(wc.getURL());
    const decision = evaluatePermissionFrame(wc, permission, details, fallbackOrigin);
    if (decision.action === 'deny') {
      notePermissionDeny(origin, permission, decision.detail);
      return false;
    }
    if (decision.action === 'warn') {
      recordSecurityEvent('permission-frame', 'info', decision.detail, origin);
    }
    return true;
  };

  session.defaultSession.setPermissionRequestHandler((webContents, permission, callback, details) => {
    // openExternal 不再静默放行：弹一次原生确认。这里拿不到具体 URL，
    // 真正带 URL 的外部协议请求走 confirmAndOpenExternal IPC。
    if (permission === 'openExternal') {
      const choice = dialog.showMessageBoxSync(readMainWindow(), {
        type: 'question',
        buttons: ['允许', '拒绝'],
        defaultId: 1,
        cancelId: 1,
        title: '网站请求打开外部程序',
        message: '当前网站请求调用系统外部应用，是否允许？'
      });
      callback(choice === 0);
      return;
    }

    if (!enforceFrameGuard(webContents, permission, details)) {
      callback(false);
      return;
    }

    if (permission === 'clipboard-read') {
      const clipOrigin = urlResolve.safeOrigin(webContents.getURL());
      const clipVerdict = clipboardReadOrigin.decideClipboardRead({
        permission,
        pageUrl: webContents.getURL(),
        requestOrigin: details && details.requestingUrl,
        isTopFrame: !(details && details.isMainFrame === false),
        tabActive: getCurrentTabWebContents() === webContents
      });
      if (!clipVerdict.allow) {
        recordSecurityEvent('clipboard-read-blocked', 'warn',
          `剪贴板读取被拒（${clipboardReadOrigin.describeReason(clipVerdict.reason)}）: ${clipVerdict.detail}`, clipOrigin);
        callback(false);
        return;
      }
    }

    if (SENSITIVE_PAGE_PERMISSIONS.has(permission)) {
      const origin = urlResolve.safeOrigin(webContents.getURL());

      // 用户对该站点记忆过"始终允许/拒绝"：直接兑现决定，不再弹询问条。
      const remembered = getRememberedPermission(origin, permission);
      if (remembered === 'allow' || remembered === 'deny') {
        callback(remembered === 'allow');
        return;
      }

      const requestId = String(++permissionSeq);
      let settled = false;
      let timer = null;
      const cleanup = () => {
        if (timer) clearTimeout(timer);
        webContents.removeListener('destroyed', onDestroyed);
        pendingPermissionRequests.delete(requestId);
      };
      const finish = (granted) => {
        if (settled) return;
        settled = true;
        cleanup();
        try { callback(!!granted); } catch {}
      };
      const onDestroyed = () => finish(false);
      webContents.once('destroyed', onDestroyed);
      timer = setTimeout(() => finish(false), permissionDecisionTimeoutMs);
      pendingPermissionRequests.set(requestId, { finish, origin, permission });

      sendToRenderer('permission-request', {
        requestId,
        tabId: tabIdForContents(webContents),
        permission,
        origin,
        mediaTypes: Array.isArray(details && details.mediaTypes) ? details.mediaTypes.slice(0, 4) : [],
      });
      return;
    }

    // 其余非敏感、通常由用户手势触发的权限（fullscreen / pointerLock / clipboard 等）维持白名单。
    // 不在白名单内的权限（hid / serial / bluetooth / window-management /
    // idle-detection / usb 等设备或指纹类权限）默认拒绝并留痕。以前这里直接
    // 用 Set.has 兜底，虽然结果也是 false，但被拦的请求完全没有记录，用户无从
    // 知道某个网站在尝试枚举蓝牙 / HID 设备。
    const allowed = ALLOWED_PERMISSIONS.has(permission);
    if (!allowed) {
      const origin = urlResolve.safeOrigin(webContents.getURL());
      recordSecurityEvent('permission-blocked', 'warn',
        `网站请求了未授权的浏览器权限: ${permission}`, origin);
    }
    callback(allowed);
  });
  session.defaultSession.setPermissionCheckHandler((webContents, permission, requestingOrigin, details) => {
    if (permission === 'openExternal') return false;
    if (!enforceFrameGuard(webContents, permission, details, requestingOrigin)) return false;
    if (permission === 'clipboard-read') {
      const checkVerdict = clipboardReadOrigin.decideClipboardRead({
        permission,
        pageUrl: webContents && typeof webContents.getURL === 'function' ? webContents.getURL() : '',
        requestOrigin: requestingOrigin,
        isTopFrame: !(details && details.isMainFrame === false),
        tabActive: getCurrentTabWebContents() === webContents
      });
      if (!checkVerdict.allow) {
        const checkOrigin = urlResolve.safeOrigin(webContents.getURL());
        recordSecurityEvent('clipboard-read-blocked', 'warn',
          `剪贴板读取检查被拒（${clipboardReadOrigin.describeReason(checkVerdict.reason)}）: ${checkVerdict.detail}`, checkOrigin);
      }
      return checkVerdict.allow;
    }
    // 敏感权限：记忆为"允许"才承认；记忆为"拒绝"或未记忆一律返回 false，
    // 让站点真正调用时走 request handler（弹询问条或直接兑现拒绝）。
    if (SENSITIVE_PAGE_PERMISSIONS.has(permission)) {
      const origin = urlResolve.safeOrigin(webContents.getURL());
      return getRememberedPermission(origin, permission) === 'allow';
    }
    return ALLOWED_PERMISSIONS.has(permission);
  });

  // setPermissionRequestHandler 不覆盖 navigator.hid / serial / usb /
  // bluetooth 的"设备选择授权"——那是另一条独立回调。不设置时各版本
  // Electron 的默认行为不一致（部分版本直接放行设备选择弹窗），这里显式
  // 一律拒绝：浏览器场景下网页没有正当理由直连本机 HID / 串口 / USB 设备。
  if (typeof session.defaultSession.setDevicePermissionHandler === 'function') {
    session.defaultSession.setDevicePermissionHandler((details) => {
      const origin = urlResolve.safeOrigin(details && details.origin ? details.origin : '');
      const mediaType = (details && (details.deviceType || details.device && details.device.deviceClass)) || 'unknown-device';
      recordSecurityEvent('device-permission-blocked', 'warn',
        `网站尝试获取本机设备（${mediaType} / ${details && details.permissionType ? details.permissionType : '未知'}）`,
        origin);
      return false;
    });
  }

  // 屏幕共享（getDisplayMedia）走独立回调，setPermissionRequestHandler 不覆盖它。
  // 不设置时嵌入式视图在各 Electron 版本行为不一致，存在静默录屏风险；这里显式
  // 一律拒绝（即便内部 cosy: 页面也不放行），并按画面/仅音频/畸形分类留痕。
  if (displayGuard.isDisplayMediaHandlerAvailable(session.defaultSession)) {
    session.defaultSession.setDisplayMediaRequestHandler((request, callback) => {
      const decision = displayGuard.decideDisplayMedia(request);
      const mediaText = decision.mediaTypes.join(',') || 'unknown';
      recordSecurityEvent('display-capture-blocked', 'warn',
        `网站请求屏幕共享已拒绝（${decision.reason}；${mediaText}）`, decision.origin);
      // callback 必须回一个 video：undefined 才表示拒绝；不回会导致 Promise 悬挂。
      try { callback({ video: undefined, audio: undefined }); } catch {}
    });
  }

  // 渲染层询问条回传决策；找不到对应请求时忽略。
  // payload.remember=true 表示用户勾了"始终…"，按 origin+permission 持久化。
  ipcMain.handle('permission-response', (event, payload = {}) => {
    if (!isMainSender(event)) return { success: false };
    const { requestId, granted, remember } = payload || {};
    const entry = pendingPermissionRequests.get(String(requestId));
    if (!entry || typeof entry.finish !== 'function') return { success: false, reason: 'unknown request' };
    if (remember) rememberPermission(entry.origin, entry.permission, granted ? 'allow' : 'deny');
    entry.finish(!!granted);
    return { success: true, remembered: !!remember };
  });

  // ===== 站点权限管理页（cosy://permissions）专用 IPC，全部仅主框架可调 =====
  ipcMain.handle('list-permission-decisions', (event) => {
    if (!isMainSender(event)) return [];
    return listPermissionDecisions();
  });
  ipcMain.handle('reset-permission-decision', (event, payload = {}) => {
    if (!isMainSender(event)) return { success: false };
    const origin = String(payload.origin || '');
    const permission = String(payload.permission || '');
    if (!isRememberableOrigin(origin) || !REMEMBERED_PAGE_PERMISSIONS.has(permission)) {
      return { success: false, reason: 'invalid target' };
    }
    return { success: forgetPermission(origin, permission) };
  });
  ipcMain.handle('clear-permission-decisions', (event, payload = {}) => {
    if (!isMainSender(event)) return { success: false };
    const origin = String(payload.origin || '');
    if (!isRememberableOrigin(origin)) return { success: false, reason: 'invalid origin' };
    return { success: true, removed: clearPermissionDecisionsForOrigin(origin) };
  });
  ipcMain.handle('audit-permission-decisions', (event) => {
    if (!isMainSender(event)) return { total: 0 };
    return auditPermissionDecisions();
  });
  ipcMain.handle('prune-permission-decisions', (event) => {
    if (!isMainSender(event)) return { success: false };
    return prunePermissionDecisions();
  });

  // ===== 安全事件中心（cosy://security）只读 / 清空 IPC，仅主框架可调 =====
  ipcMain.handle('list-security-events', (event, payload = {}) => {
    if (!isMainSender(event)) return [];
    return listSecurityEvents(String(payload.type || ''), Number(payload.limit) || 200);
  });
  ipcMain.handle('clear-security-events', (event) => {
    if (!isMainSender(event)) return { success: false };
    return { success: true, cleared: clearSecurityEvents() };
  });

  // ===== CSP 违规上报（renderer send）/ 面板读取清空（invoke），仅内部帧 =====
  // 上报用 send 而不是 invoke：违规是"通知"语义，页面不该等待也不该拿到
  // 是否被记录的回执之外的信息；这里也不回包，避免成为时序探测面。
  ipcMain.on('report-csp-violation', (event, payload) => {
    recordCspViolationFromRenderer(event.senderFrame, payload);
  });
  ipcMain.handle('list-csp-reports', (event, payload = {}) => {
    if (!isMainSender(event)) return [];
    return listCspReports(Number(payload.limit) || 200);
  });
  ipcMain.handle('clear-csp-reports', (event) => {
    if (!isMainSender(event)) return { success: false };
    return { success: true, cleared: clearCspReports() };
  });
  ipcMain.handle('remove-csp-report', (event, payload = {}) => {
    if (!isMainSender(event)) return { success: false };
    return { success: true, removed: removeCspReport(payload && payload.id) };
  });
  ipcMain.handle('get-csp-report-stats', (event) => {
    if (!isMainSender(event)) return { groups: 0, totalHits: 0 };
    return getCspReportStats();
  });
  ipcMain.handle('list-header-grades', (event, payload = {}) => {
    if (!isMainSender(event)) return [];
    return listHeaderGrades(Number(payload.limit) || 200);
  });
  ipcMain.handle('clear-header-grades', (event) => {
    if (!isMainSender(event)) return { success: false };
    return { success: true, cleared: clearHeaderGrades() };
  });
  ipcMain.handle('get-header-grade-stats', (event) => {
    if (!isMainSender(event)) return { hosts: 0, byGrade: {}, insecureHosts: 0 };
    return getHeaderGradeStats();
  });

  // ===== 后台跨主机连接台账（cosy://security）IPC，仅主框架可调 =====
  ipcMain.handle('list-request-log', (event, payload = {}) => {
    if (!isMainSender(event)) return [];
    return listRequestLogEntries(Number(payload.limit) || 200);
  });
  ipcMain.handle('clear-request-log', (event) => {
    if (!isMainSender(event)) return { success: false };
    return { success: true, cleared: clearRequestLog() };
  });
  ipcMain.handle('get-request-log-stats', (event) => {
    if (!isMainSender(event)) {
      return { hosts: 0, requests: 0, blocked: 0, backgroundHosts: 0, insecureHosts: 0 };
    }
    return getRequestLogStats();
  });

  // ===== 品牌仿冒 / 拼写劫持命中台账（cosy://security）IPC，仅主框架可调 =====
  ipcMain.handle('list-brand-spoofs', (event, payload = {}) => {
    if (!isMainSender(event)) return [];
    return listBrandSpoofEntries(Number(payload.limit) || 200);
  });
  ipcMain.handle('clear-brand-spoofs', (event) => {
    if (!isMainSender(event)) return { success: false };
    return { success: true, cleared: clearBrandSpoofs() };
  });
  ipcMain.handle('get-brand-spoof-stats', (event) => {
    if (!isMainSender(event)) {
      return { hosts: 0, byReason: {}, distinctBrands: 0 };
    }
    return getBrandSpoofStats();
  });

  // ===== 下载完整性校验（cosy://hashes）IPC，仅主框架可调 =====
  ipcMain.handle('list-download-hashes', (event, payload = {}) => {
    if (!isMainSender(event)) return [];
    return listDownloadHashes(Number(payload.limit) || 200);
  });
  ipcMain.handle('verify-download-hash', (event, payload = {}) => {
    if (!isMainSender(event)) return { ok: false, reason: 'denied' };
    return verifyDownloadHashById(payload.id, payload.expected);
  });
  ipcMain.handle('remove-download-hash', (event, payload = {}) => {
    if (!isMainSender(event)) return { success: false };
    return { success: true, removed: removeDownloadHashRecord(payload.id) };
  });
  ipcMain.handle('clear-download-hashes', (event) => {
    if (!isMainSender(event)) return { success: false };
    return { success: true, cleared: clearDownloadHashes() };
  });
  ipcMain.handle('hash-local-file', (event) => {
    if (!isMainSender(event)) return { ok: false, reason: 'denied' };
    return hashLocalFileViaDialog();
  });

  // ===== 下载风险台账（cosy://security）IPC，仅主框架可调 =====
  ipcMain.handle('list-download-risks', (event, payload = {}) => {
    if (!isMainSender(event)) return [];
    return listDownloadRisks(Number(payload.limit) || 200);
  });
  ipcMain.handle('clear-download-risks', (event) => {
    if (!isMainSender(event)) return { success: false };
    return { success: true, cleared: clearDownloadRisks() };
  });

  // ===== 链接净化（去追踪参数 / 解跳转包装），仅主框架可调 =====
  // 纯字符串处理，不触网；供安全中心的“净化复制链接”工具调用。
  ipcMain.handle('clean-share-url', (event, payload = {}) => {
    if (!isMainSender(event)) return { ok: false, reason: 'denied' };
    if (typeof payload.url !== 'string' || payload.url.length > 4096) {
      return { ok: false, reason: 'invalid-url' };
    }
    const res = urlClean.cleanShareTarget(payload.url);
    return {
      ok: true,
      url: res.url,
      changed: !!res.changed,
      unwrapped: !!res.unwrapped,
      removedKeys: Array.isArray(res.removedKeys) ? res.removedKeys.slice(0, 50) : [],
    };
  });

  return { setupPermissionHandlers };
}

module.exports = { create };
