'use strict';

function create(ctx) {
  const {
    BrowserWindow, RAW_IPC_SEND_ALLOWED, RAW_IPC_SYNC_ALLOWED, WebContentsView, app, captureGuard,
    captureStates, childWindowGuard, childWindowStates, consoleGuard, consoleStates, crashGuard,
    crashReloadCounts, crashStates, createNewTab, cursorGuard, cursorStates, devicerGuard,
    devtoolsGuard, devtoolsSwitchGuard, devtoolsSwitchStates, dialog, dialogGuard, dialogStates,
    displayGuard, entryGuard, entryStates, frameGuard, frameStates, fullscreenGuard,
    getContentsState, getCurrentTabWebContents, goneGuard, handleFrameNavigationAttempt, hoverGuard, hoverStates,
    inpageGuard, inpageStates, ipcChannelGuard, ipcChannelStates, isSafeUrl, isolatedChildContents,
    launchExternalWithPrompt, mediaGuard, mediaStates, navGuard, originOfContents, popupGuard,
    preloadGuard, printGuard, recordSecurityEvent, redirectChainStates, redirectGuard, remoteGuard,
    remoteStates, revokeGuard, revokeStates, schemeOrigin, securityBoundaryHub, sendToRenderer,
    session, storageAccessGuard, storageAccessStates, themeGuard, themeStates, titleStates,
    unloadGuard, unloadStates, webContents, webviewHarden, zoomGuard,
  } = ctx;
  const readCrashRecoveryEnabled = ctx.readCrashRecoveryEnabled;
  const readMainWindow = ctx.readMainWindow;
  const readTabs = ctx.readTabs;

  // GPU 进程崩溃时通知界面（Electron 14+ 的统一子进程事件）。GPU 进程通常会自动重启，
  // 这里只提示一次，避免用户面对“画面突然空白却不知道发生了什么”。
  app.on('child-process-gone', (_gpuEvent, details) => {
    if (details && details.type === 'GPU') {
      sendToRenderer('gpu-process-gone', { reason: details.reason || 'unknown' });
    }
  });

  // handleUnsafeNavigation 对主框架导航做 IDN 同形异义字 / 降级检查。
  // 返回 true 表示已拦截（调用方需 preventDefault）。block 直接挡；warn 弹原生
  // 确认，用户放弃则同样挡掉。内部页（cosy://）不参与判定。
  function handleUnsafeNavigation(targetContents, navUrl) {
    try {
      if (typeof navUrl !== 'string' || !navUrl) return false;
      if (navUrl.startsWith('cosy://') || navUrl.startsWith('about:')) return false;
      let currentUrl = '';
      try { currentUrl = targetContents.getURL(); } catch { currentUrl = ''; }
      const decision = navGuard.decideNavigation({ currentUrl, targetUrl: navUrl });
      if (decision.action === navGuard.RISK_OK) return false;

      const reasonText = [].concat(decision.reasons.host || [], decision.reasons.nav || []).join('; ');
      if (decision.action === navGuard.RISK_BLOCK) {
        recordSecurityEvent('nav-blocked', 'warn',
          `已阻止可疑导航: ${navUrl} (${reasonText})`, originOfContents(targetContents));
        sendToRenderer('show-toast', '已阻止一次可疑导航（仿冒域名或安全降级）');
        return true;
      }

      // warn：让用户在原生对话框里明确选择。
        const choice = dialog.showMessageBoxSync(readMainWindow(), {
          type: 'warning',
          buttons: ['返回安全页面', '仍然继续'],
          defaultId: 0,
          cancelId: 0,
          title: '安全提示：可疑的网站地址',
          message: '这个网址可能是仿冒网站或存在安全降级，是否仍要访问？',
          detail: [
            `地址：${navUrl}`,
            `原因：${reasonText || '可疑域名特征'}`,
            '',
            '该地址可能使用了与正规网站极其相似的字符，或正从不安全的明文连接加载。',
            '继续访问可能导致账号、密码等信息泄露。',
          ].join('\n'),
          noLink: true,
        });
        recordSecurityEvent('nav-warn', 'info',
          `可疑导航提示 ${choice === 1 ? '用户继续' : '用户返回'}: ${navUrl} (${reasonText})`,
          originOfContents(targetContents));
        return choice !== 1;
    } catch (guardErr) {
      // 守卫自身异常绝不能阻断正常浏览：失败放行并留痕。
      recordSecurityEvent('nav-guard-error', 'info',
        `导航守卫异常放行: ${String(guardErr && guardErr.message || guardErr)}`, '');
      return false;
    }
  }

  app.on('web-contents-created', (_event, contents) => {
    // 主窗口 UI 自己管 navigation，跳过；只给页面 tab 兜底
    if (contents === readMainWindow()?.webContents) return;

    // 每个页面 contents 独立维护一条服务端重定向链状态（降级/环路/钓鱼判定）。
    const redirectState = redirectGuard.createRedirectState(Date.now());
    contents.on('destroyed', () => {
      redirectChainStates.delete(contents.id);
      dialogStates.delete(contents.id);
      unloadStates.delete(contents.id);
      titleStates.delete(contents.id);
      inpageStates.delete(contents.id);
      consoleStates.delete(contents.id);
      hoverStates.delete(contents.id);
      themeStates.delete(contents.id);
      mediaStates.delete(contents.id);
      crashStates.delete(contents.id);
      cursorStates.delete(contents.id);
      entryStates.delete(contents.id);
      childWindowStates.delete(contents.id);
      frameStates.delete(contents.id);
      captureStates.delete(contents.id);
      devtoolsSwitchStates.delete(contents.id);
      remoteStates.delete(contents.id);
      ipcChannelStates.delete(contents.id);
      revokeStates.delete(contents.id);
      storageAccessStates.delete(contents.id);
    });
    redirectChainStates.set(contents.id, redirectState);
    // 顶层真正落地导航后，重定向链归零，开始统计下一条链。
    contents.on('did-navigate', () => {
      redirectGuard.resetState(redirectState, Date.now());
      // 进入新的顶层文档：强留页配额与同文档导航洪泛计数都按页面生命周期重置。
      unloadGuard.resetForNavigation(unloadStates.get(contents.id));
      inpageGuard.resetForNavigation(inpageStates.get(contents.id));
      // r32：各事件通道的洪泛/冷却配额随主导航重置（插件崩溃计数同样随文档生命周期清空）。
      consoleGuard.resetForNavigation(consoleStates.get(contents.id));
      hoverGuard.resetForNavigation(hoverStates.get(contents.id));
      themeGuard.resetForNavigation(themeStates.get(contents.id));
      mediaGuard.resetForNavigation(mediaStates.get(contents.id));
      crashGuard.resetForNavigation(crashStates.get(contents.id));
      cursorGuard.resetForNavigation(cursorStates.get(contents.id));
      entryGuard.resetForNavigation(entryStates.get(contents.id));
      // r33：换文档后子窗口 / iframe / 捕获 / DevTools 开关配额随生命周期重置。
      childWindowGuard.resetForNavigation(childWindowStates.get(contents.id));
      frameGuard.resetForNavigation(frameStates.get(contents.id), Date.now());
      captureGuard.resetForNavigation(captureStates.get(contents.id), Date.now());
      devtoolsSwitchGuard.resetForNavigation(devtoolsSwitchStates.get(contents.id), Date.now());
      remoteGuard.resetForNavigation(remoteStates.get(contents.id));
      ipcChannelGuard.resetForNavigation(ipcChannelStates.get(contents.id));
      // r34：换顶层文档后，设备撤销去重与跨框架存储访问分桶按新源重新计，避免把
      // 上一个文档的跨源桶/撤销冷却带到新页面。删除后下次事件经 getContentsState 重建。
      revokeStates.delete(contents.id);
      storageAccessStates.delete(contents.id);
    });

    // handleRedirect 在 navguard 的来源矩阵之前先做“重定向专项”判定，返回 true
    // 表示已拦截（调用方应 preventDefault）。
    const handleRedirect = (fromUrl, toUrl) => {
      let currentUrl = fromUrl || '';
      if (!currentUrl) {
        try { currentUrl = contents.getURL(); } catch {}
      }
      const verdict = redirectGuard.decideRedirect(
        redirectState, { fromUrl: currentUrl, toUrl }, Date.now());
      if (verdict.action === redirectGuard.REDIRECT_BLOCK) {
        recordSecurityEvent('redirect-blocked', 'warn',
          `危险重定向已拦截（${verdict.reasons.map(redirectGuard.describeReason).join('；')}）: ${toUrl}`,
          originOfContents(contents));
        return true;
      }
      return false;
    };

    contents.setWindowOpenHandler(({ url }) => {
      // 兜底窗口：外部协议走确认流，不允许直接 openExternal。
      const extScheme = normalizeExternalScheme(url);
      if (CONFIRMABLE_EXTERNAL_SCHEMES.has(extScheme)) {
        launchExternalWithPrompt(url, originOfContents(contents), true);
        return { action: 'deny' };
      }
      // 兜底窗口同样禁止 javascript:/data:/file: 等危险协议弹窗。
      const fallbackPopup = popupGuard.decidePopup({
        currentUrl: (() => { try { return contents.getURL(); } catch { return ''; } })(),
        targetUrl: url,
      });
      if (fallbackPopup.action === 'block') {
        recordSecurityEvent('popup-blocked', 'warn', `拦截危险协议弹窗: ${url}`, originOfContents(contents));
        return { action: 'deny' };
      }
      if (!isSafeUrl(url)) return { action: 'deny' };
      // 从 tab 里点 _blank 的，统一丢回我们的 createNewTab
      setImmediate(() => createNewTab(url));
      return { action: 'deny' };
    });

    // navigator.bluetooth.requestDevice 的设备选择事件。无人监听时部分平台会
    // 自动选中枚举到的第一个蓝牙设备继续配对，等于把本机蓝牙设备暴露给网页；
    // 这里显式 callback('') 取消选择并留痕。
    contents.on('select-bluetooth-device', (btEvent, btDevices, btCallback) => {
      try { btEvent.preventDefault(); } catch {}
      const verdict = displayGuard.decideBluetoothSelection({
        url: (() => { try { return contents.getURL(); } catch { return ''; } })(),
        devices: btDevices,
      });
      recordSecurityEvent('bluetooth-blocked', 'warn',
        `网站请求蓝牙设备已取消（枚举 ${verdict.deviceCount} 台）`, verdict.origin);
      try { btCallback(''); } catch {}
    });

    // 串口 / HID / USB 的“设备选择”回调与蓝牙同理：不监听时部分平台会自动选中枚举到
    // 的第一个设备。网页没有理由独占本机串口/HID/USB（U 盾、键盘、烧录器等），统一
    // 显式取消选择（callback('')），绝不依赖默认行为。
    const contentsOriginUrl = () => {
      try { return contents.getURL(); } catch { return ''; }
    };
    contents.on('select-serial-port', (seEvent, portList, _seWc, seCallback) => {
      try { seEvent.preventDefault(); } catch {}
      const v = devicerGuard.decideDeviceChooser({
        kind: devicerGuard.KIND_SERIAL, originUrl: contentsOriginUrl(), portList,
      });
      recordSecurityEvent('serial-blocked', 'warn',
        `网站请求${devicerGuard.describeKind(v.kind)}设备已取消（枚举 ${v.deviceCount} 台）`, v.origin);
      try { seCallback(''); } catch {}
    });
    contents.on('select-hid-device', (hidEvent, hidDetails, hidCallback) => {
      try { hidEvent.preventDefault(); } catch {}
      const v = devicerGuard.decideDeviceChooser({
        kind: devicerGuard.KIND_HID, originUrl: contentsOriginUrl(), details: hidDetails,
      });
      recordSecurityEvent('hid-blocked', 'warn',
        `网站请求${devicerGuard.describeKind(v.kind)}设备已取消（枚举 ${v.deviceCount} 台）`, v.origin);
      try { hidCallback(''); } catch {}
    });
    contents.on('select-usb-device', (usbEvent, usbDetails, usbCallback) => {
      try { usbEvent.preventDefault(); } catch {}
      const v = devicerGuard.decideDeviceChooser({
        kind: devicerGuard.KIND_USB, originUrl: contentsOriginUrl(), details: usbDetails,
      });
      recordSecurityEvent('usb-blocked', 'warn',
        `网站请求${devicerGuard.describeKind(v.kind)}设备已取消（枚举 ${v.deviceCount} 台）`, v.origin);
      try { usbCallback(''); } catch {}
    });

    // 本浏览器用 WebContentsView 承载页面，从不使用 <webview> 标签。
    // 若有页面尝试 attach webview，一律阻止：webview 默认能携带自己的
    // webPreferences（nodeIntegration/disablewebsecurity），是常见提权通道。
    contents.on('will-attach-webview', (attachEvent, webPreferences, params) => {      // 完整的 webview 挂载审计：src 仅允许远程 http(s)，guest 自带 preload /
      // Node 集成 / 关闭安全开关 / 挂载主会话分区等一律收口（见 webviewharden.js）。
      const verdict = webviewHarden.review(webPreferences, params);
      if (verdict.reasons.length) {
        recordSecurityEvent('webview-blocked', verdict.blocked ? 'warn' : 'info',
          `webview 挂载审计: ${verdict.reasons.map(webviewHarden.describeReason).join('；')}`,
          originOfContents(contents));
      }
      if (verdict.blocked) {
        attachEvent.preventDefault();
        return;
      }
      // src 合法时也用安全基线整体覆盖 guest 配置，杜绝任何残留提权项。
      for (const key of Object.keys(webPreferences)) delete webPreferences[key];
      Object.assign(webPreferences, verdict.prefs);
    });

    // 主框架导航：http(s)/file/cosy 放行，mailto/tel 走按站点记忆的确认弹窗，
    // 其它外部协议（ms-*:/smb:/vbscript: 等）直接阻止。
    contents.on('will-navigate', (navEvent, url) => {
      // 来源矩阵：远程网页 / data / blob 等不可信上下文不得把顶层框架顶到
      // file:// 本地资源或 cosy: 特权内部页（地址栏 loadURL 不触发本事件，
      // 故浏览器自身打开本地文件不受影响）。
      let navInitiator = '';
      try { navInitiator = contents.getURL(); } catch {}
      try {
        const boundary = schemeOrigin.evaluate(url, navInitiator);
        if (boundary.action === 'block') {
          recordSecurityEvent('origin-boundary-blocked', 'warn',
            `${schemeOrigin.describeBlock(boundary.reason)}: ${String(url).slice(0, 200)}`,
            navInitiator);
          sendToRenderer('show-toast', '已阻止网页导航到本地文件或浏览器内部页面');
          navEvent.preventDefault();
          return;
        }
      } catch { /* 判定异常不干预，交后续链路 */ }
      // 导航安全：IDN 同形异义字钓鱼 / 混合脚本域名直接拦；整词同形 / Punycode
      // 与 HTTPS→HTTP 同站降级弹原生确认；跨主机 http 降级直接拦。
      if (handleUnsafeNavigation(contents, url)) {
        navEvent.preventDefault();
        return;
      }
      if (handleFrameNavigationAttempt(contents, url, true)) {
        navEvent.preventDefault();
      }
    });

    // 子框架导航：这是历史代码漏掉的面——iframe src="ms-word:.." 或子框架 302
    // 到外部协议同样能唤起本机程序。子框架只允许纯 Web 协议，其余一律取消。
    contents.on('will-frame-navigate', (frameEvent, url, isMainFrame) => {
      // 主框架导航已由上面的 will-navigate 统一处理（它还要更新地址栏 / 历史），
      // 这里只接管子框架，否则一次导航会弹两次确认框。
      if (isMainFrame) return;
      if (handleFrameNavigationAttempt(contents, url, false)) {
        frameEvent.preventDefault();
      }
    });

    // 页内查找结果转发：findInPage 只会作用于活动标签，所以这里也只把
    // 当前活动 webContents 的匹配结果送回主界面，更新“第 x / y 个匹配”。
    // 非活动标签的结果直接忽略，避免后台标签覆盖计数。
    contents.on('found-in-page', (_findEvent, result) => {
      if (contents !== getCurrentTabWebContents()) return;
      sendToRenderer('found-in-page-result', {
        activeMatchOrdinal: result.activeMatchOrdinal || 0,
        matches: result.matches || 0,
      });
    });

    // 服务端 302 也可能把框架重定向到外部协议（下载站常见手法）。
    // will-redirect 覆盖主框架；will-frame-redirect 覆盖子框架（旧 Electron
    // 没有该事件时监听器静默不生效，主框架面仍被兜住）。
    // 先走重定向专项守卫（降级/环路/钓鱼/危险 scheme），再走 navguard 来源矩阵。
    contents.on('will-redirect', (redirectEvent, url, isRedirect) => {
      if (handleRedirect('', url)) {
        redirectEvent.preventDefault();
        return;
      }
      if (handleFrameNavigationAttempt(contents, url, true)) {
        redirectEvent.preventDefault();
      }
    });

    contents.on('will-frame-redirect', (redirectEvent, url, isMainFrame) => {
      if (isMainFrame) return;
      if (handleRedirect('', url)) {
        redirectEvent.preventDefault();
        return;
      }
      if (handleFrameNavigationAttempt(contents, url, false)) {
        redirectEvent.preventDefault();
      }
    });

    // ===== 渲染进程崩溃 / 卡死恢复 =====
    // 现代浏览器在某个标签的渲染进程崩溃后会给横幅而不是整窗静默死掉。
    // 崩溃 / OOM 自动重载“一次”（第二次不再自动，避免崩溃循环把 CPU 打满），
    // 被系统杀死(killed)不自动重载；无响应时给横幅让用户选“等待 / 强制刷新”。
    contents.on('render-process-gone', (_goneEvent, details) => {
      const tab = readTabs().find(t => t.view && t.view.webContents === contents);
      let goneUrl = tab?.url || '';
      if (!goneUrl) {
        try { goneUrl = contents.getURL(); } catch {}
      }
      // 用 goneguard 做窗口内有界定速 + 冷却 + 熔断，并禁止自动重载 data:/blob:
      // 等瞬时上下文（见 goneguard.js），替代旧的“只重载一次”裸计数。
      const now = Date.now();
      let goneState = crashReloadCounts.get(contents.id);
      if (!goneState) {
        goneState = goneGuard.createState(now);
        crashReloadCounts.set(contents.id, goneState);
      }
      const decision = goneGuard.decideReload(goneState, goneUrl, now);
      const recoverable = details.reason === 'crashed' || details.reason === 'oom';
      const payload = {
        tabId: contents.id,
        reason: details.reason || 'unknown',
        exitCode: typeof details.exitCode === 'number' ? details.exitCode : null,
        url: goneUrl,
        title: tab?.title || '',
        autoReloaded: false,
        recovery: decision.reason,
      };
      if (readCrashRecoveryEnabled() && recoverable && decision.action === 'reload' &&
          !contents.isDestroyed()) {
        payload.autoReloaded = true;
        setTimeout(() => {
          if (!contents.isDestroyed()) contents.reload();
        }, 400);
      } else if (decision.action === 'error-page') {
        // 熔断 / 限频 / 不可重载上下文：留痕，界面据此显示手动恢复横幅。
        recordSecurityEvent('renderer-gone', 'info',
          `${goneGuard.describeReason(decision.reason)}（${details.reason || 'unknown'}）`,
          goneUrl);
      }
      sendToRenderer('renderer-gone', payload);
    });

    // 页面恢复正常后，把该标签的崩溃处置状态清零，给下次真正的崩溃留出恢复额度。
    contents.on('did-finish-load', () => crashReloadCounts.delete(contents.id));

    contents.on('unresponsive', () => {
      // 无响应事件在卡死期间会连续触发，用 goneguard 冷却去抖，避免横幅轰炸。
      const now = Date.now();
      let goneState = crashReloadCounts.get(contents.id);
      if (!goneState) {
        goneState = goneGuard.createState(now);
        crashReloadCounts.set(contents.id, goneState);
      }
      const verdict = goneGuard.decideUnresponsive(goneState, now);
      if (verdict.notify) {
        sendToRenderer('renderer-unresponsive', { tabId: contents.id });
      }
    });
    contents.on('responsive', () => {
      sendToRenderer('renderer-responsive', { tabId: contents.id });
    });

    // JS 模态框（alert/confirm/prompt）轰炸收口：滑动窗口配额 + 同文案去抖 + 冷却。
    // beforeunload 类型不在这里处理，交给下方 will-prevent-unload 的 unloadguard。
    contents.on('dialog', (event, type, url, text) => {
      if (dialogGuard.isBeforeUnload(type)) return;
      const st = getContentsState(dialogStates, contents.id, dialogGuard.createDialogState);
      const v = dialogGuard.decideDialog(
        st,
        { type, message: text, originUrl: url || originOfContents(contents) },
        Date.now()
      );
      if (v.decision === dialogGuard.DIALOG_SUPPRESS) {
        event.preventDefault();
        const severity = v.reason === dialogGuard.SUPPRESS_DUPLICATE ? 'info' : 'warn';
        recordSecurityEvent('dialog-blocked', severity,
          dialogGuard.describeDialogReason(v.reason), v.origin || originOfContents(contents));
      }
    });

    // 页面调 window.close() 之前触发的 beforeunload。unloadguard 给真实“未保存修改”
    // 保留每页面几次确认额度；恶意页反复强留则越限后直接放行关闭/导航（不再弹模态）。
    contents.on('will-prevent-unload', (event) => {
      const st = getContentsState(unloadStates, contents.id, unloadGuard.createUnloadState);
      const v = unloadGuard.decideUnload(st, Date.now());
      if (v.decision === unloadGuard.UNLOAD_LEAVE) {
        // 不调用 preventDefault：尊重用户的关闭/导航意图，页面照常卸载。
        recordSecurityEvent('unload-bypass', 'warn',
          unloadGuard.describeUnloadReason(v.reason), originOfContents(contents));
        return;
      }
      event.preventDefault();
      const choice = dialog.showMessageBoxSync(readMainWindow(), {
        type: 'question',
        buttons: ['离开此页', '留在此页'],
        defaultId: 1,
        cancelId: 1,
        title: '确认离开',
        message: '您有尚未保存的更改。确定要离开此页面吗？'
      });
      if (choice === 0) {
        contents.destroy();
      }
    });

    // ===== 全屏 / 键盘锁 / 打印 / 缩放 / DevTools 链接收口（每 contents 独立状态）=====
    const fsState = fullscreenGuard.createFullscreenState(Date.now());
    const printState = printGuard.createPrintState(Date.now());
    const zoomState = zoomGuard.createZoomState(Date.now());
    const preloadErrState = preloadGuard.createPreloadErrorState(Date.now());
    let zoomFlushTimer = null;

    const currentContentsUrl = () => {
      try { return contents.getURL(); } catch { return ''; }
    };
    const broadcastZoomLevel = (level) => {
      try {
        sendToRenderer('zoom-level-changed', {
          percent: zoomGuard.zoomLevelToPercent(level),
          factor: Math.pow(1.2, level),
        });
      } catch {}
    };

    contents.on('enter-html-full-screen', () => {
      const r = fullscreenGuard.noteEnter(fsState, Date.now(), currentContentsUrl());
      if (r.abusive) {
        recordSecurityEvent('fullscreen-abuse', 'warn',
          fullscreenGuard.describeAbuse(fullscreenGuard.ABUSE_FLICKER), originOfContents(contents));
      }
    });
    contents.on('leave-html-full-screen', () => {
      const r = fullscreenGuard.noteLeave(fsState, Date.now());
      if (r.abusive) {
        recordSecurityEvent('fullscreen-abuse', 'warn',
          fullscreenGuard.describeAbuse(fullscreenGuard.ABUSE_FLICKER), originOfContents(contents));
      }
    });

    // 键盘锁只在该内容确处全屏时放行；窗口态请求（Esc/快捷键劫持起手式）一律阻止。
    contents.on('keyboard-lock', (event) => {
      const v = fullscreenGuard.decideKeyboardLock(
        fsState, { originUrl: currentContentsUrl() }, Date.now());
      if (v.decision === fullscreenGuard.KEYBOARD_DENY) {
        event.preventDefault();
        recordSecurityEvent('keyboard-lock-blocked', 'warn',
          fullscreenGuard.describeKeyboardReason(v.reason), v.origin || originOfContents(contents));
      }
    });

    // window.print() 打印轰炸：滑动窗口配额 + 冷却，越限抑制内置打印流程。
    contents.on('print', (event) => {
      const v = printGuard.decidePrint(printState, { originUrl: currentContentsUrl() }, Date.now());
      if (v.decision === printGuard.PRINT_SUPPRESS) {
        event.preventDefault();
        recordSecurityEvent('print-blocked', 'warn',
          printGuard.describePrintReason(v.reason), v.origin || originOfContents(contents));
      }
    });

    // ctrl+滚轮缩放：量化/钳制级别，合并滚轮抖动的 IPC 广播，洪泛时暂停并留痕，
    // 平息后用一个 trailing 定时器补发最终级别（OSD 百分比不丢）。
    contents.on('zoom-changed', () => {
      let level = 0;
      try { level = contents.getZoomLevel(); } catch { level = 0; }
      const v = zoomGuard.applyZoomChange(zoomState, { level }, Date.now());
      if (v.flooded) {
        recordSecurityEvent('zoom-flood', 'info',
          zoomGuard.describeHoldReason(zoomGuard.HOLD_FLOODED), originOfContents(contents));
      }
      if (v.action === zoomGuard.ACTION_BROADCAST) {
        broadcastZoomLevel(v.level);
        return;
      }
      if (zoomFlushTimer) return;
      zoomFlushTimer = setTimeout(() => {
        zoomFlushTimer = null;
        const f = zoomGuard.flushPendingZoom(zoomState, Date.now());
        if (f.action === zoomGuard.ACTION_BROADCAST) broadcastZoomLevel(f.level);
      }, zoomGuard.ZOOM_BROADCAST_MIN_INTERVAL_MS + 5);
    });

    // DevTools 内点击链接：http/https/cosy 一律转应用内新标签页（绝不走系统外壳），
    // file/data/javascript 及任意外部应用协议直接拦截。
    contents.on('devtools-open-url', (event, url) => {
      const v = devtoolsGuard.decideDevToolsUrl(url);
      event.preventDefault();
      if (v.action === devtoolsGuard.ACTION_OPEN_TAB) {
        createNewTab(v.url);
      } else {
        recordSecurityEvent('devtools-url-blocked', 'warn',
          devtoolsGuard.describeDevToolsReason(v.reason), originOfContents(contents));
      }
    });

    contents.on('destroyed', () => {
      if (zoomFlushTimer) {
        clearTimeout(zoomFlushTimer);
        zoomFlushTimer = null;
      }
    });

    // preload 承载 IPC 白名单与 contextBridge 安全桥：加载/运行期抛错意味着安全包装
    // 可能残缺，必须按严重度留痕，并对同指纹/同标签页错误去重限流，防止错误循环刷爆日志。
    contents.on('preload-error', (event, preloadPath, error) => {
      const v = preloadGuard.decidePreloadError(
        preloadErrState,
        { preloadPath: String(preloadPath || ''), error, originUrl: currentContentsUrl() },
        Date.now());
      if (v.decision === preloadGuard.DECISION_REPORT) {
        recordSecurityEvent('preload-error', v.severity,
          preloadGuard.describePreloadError(v), v.origin || originOfContents(contents));
      }
    });

    // ===== r32：控制台 / 悬停状态栏 / 主题色 / 媒体 / 插件崩溃 / 光标 / 历史条目收口 =====
    // 说明：这些通道此前完全没有接线，页面可借其注入脏文本或打爆事件流。下列内核均为
    // per-contents 纯函数裁决；为避免“限流处理器自己刷爆安全日志”，只在“洪泛阈值首次
    // 越线”或“崩溃需要提示”这两个有界时刻 recordSecurityEvent，冷却期内的重复丢弃不记。

    // console-message：净化换行/ANSI/零宽与超长行，突发/长窗口越限后冷却丢弃。
    contents.on('console-message', (event, level, message, line, sourceId) => {
      const st = getContentsState(consoleStates, contents.id, consoleGuard.createConsoleState);
      const v = consoleGuard.decideConsole(
        st, { level, message, line, sourceId }, Date.now());
      if (v.action === consoleGuard.CONSOLE_DROP && v.reason === consoleGuard.CS_FLOOD) {
        recordSecurityEvent('console-flood', 'info',
          consoleGuard.describeConsoleReason(v.reason), originOfContents(contents));
      }
    });

    // update-target-url：悬停链接状态栏预告。只在裁决 show 时把净化后的 URL 推给渲染层
    // 显示；洪泛首次越线时清空状态栏（不残留伪造地址）并留痕，冷却期重复丢弃不再记。
    contents.on('update-target-url', (event, url) => {
      const st = getContentsState(hoverStates, contents.id, hoverGuard.createHoverState);
      const v = hoverGuard.decideHoverUrl(st, url, Date.now());
      if (v.action === hoverGuard.HOVER_SHOW) {
        try { sendToRenderer('target-url-changed', { url: v.url }); } catch {}
      } else if (v.action === hoverGuard.HOVER_DROP && v.reason === hoverGuard.DROP_FLOOD) {
        try { sendToRenderer('target-url-changed', { url: '' }); } catch {}
        recordSecurityEvent('hover-flood', 'warn',
          hoverGuard.describeHoverReason(v.reason), originOfContents(contents));
      }
    });

    // did-change-theme-color：只接受白名单颜色，高频闪烁（伪装浏览器顶栏）越限后锁定。
    contents.on('did-change-theme-color', (event, color) => {
      const st = getContentsState(themeStates, contents.id, themeGuard.createThemeState);
      const v = themeGuard.decideThemeColor(st, color, Date.now());
      if (v.action === themeGuard.THEME_DROP && v.reason === themeGuard.DROP_FLOOD) {
        recordSecurityEvent('theme-abuse', 'warn',
          themeGuard.describeThemeReason(v.reason), originOfContents(contents));
      }
    });

    // media-started-playing / media-paused：自动播放风暴/媒体键抖动收敛，维护真实播放态。
    contents.on('media-started-playing', () => {
      const st = getContentsState(mediaStates, contents.id, mediaGuard.createMediaState);
      const v = mediaGuard.decideMediaEvent(st, mediaGuard.MEDIA_STARTED, Date.now());
      if (v.action === mediaGuard.MEDIA_DROP && v.reason === mediaGuard.DROP_FLOOD) {
        recordSecurityEvent('media-flood', 'warn',
          mediaGuard.describeMediaReason(v.reason), originOfContents(contents));
      }
    });
    contents.on('media-paused', () => {
      const st = getContentsState(mediaStates, contents.id, mediaGuard.createMediaState);
      const v = mediaGuard.decideMediaEvent(st, mediaGuard.MEDIA_PAUSED, Date.now());
      if (v.action === mediaGuard.MEDIA_DROP && v.reason === mediaGuard.DROP_FLOOD) {
        recordSecurityEvent('media-flood', 'warn',
          mediaGuard.describeMediaReason(v.reason), originOfContents(contents));
      }
    });

    // plugin-crashed：净化插件名/版本（防日志注入），同一插件 30s 内的崩溃循环折叠为
    // 一次提示，折叠达上限强制汇总，计数天然有界，不会逐次弹窗/逐行刷日志。
    contents.on('plugin-crashed', (event, name, version) => {
      const st = getContentsState(crashStates, contents.id, crashGuard.createCrashState);
      const v = crashGuard.decidePluginCrash(st, name, version, Date.now());
      if (v.action === crashGuard.CRASH_NOTIFY) {
        const extra = v.suppressedSinceLastNotify > 0
          ? `（已折叠此前 ${v.suppressedSinceLastNotify} 次重复崩溃）`
          : '';
        recordSecurityEvent('plugin-crash', 'warn',
          `插件 ${v.name} ${v.version} 崩溃${extra}`, originOfContents(contents));
      }
    });

    // cursor-changed：类型白名单 + 自定义光标位图边长/字节/缩放校验 + 抖动洪泛冷却；
    // 任何非法/越限都回落 default 光标，避免超大位图 IPC 与高频切换 DoS。
    contents.on('cursor-changed', (event, type, image, scale) => {
      const st = getContentsState(cursorStates, contents.id, cursorGuard.createCursorState);
      let imageInfo = null;
      if (type === 'custom' && image && typeof image.getSize === 'function') {
        try {
          const size = image.getSize();
          let bytes = 0;
          try { const bmp = image.getBitmap(); bytes = Buffer.isBuffer(bmp) ? bmp.length : 0; } catch {}
          imageInfo = { width: size && size.width, height: size && size.height, bytes };
        } catch {
          imageInfo = null;
        }
      }
      const v = cursorGuard.decideCursorChange(st, type, imageInfo, scale, Date.now());
      // 非法类型/位图/缩放或抖动越限统一回落 default：Electron 不暴露逐事件设置光标的
      // 稳定 API，这里通过有界裁决丢弃异常事件流，仅在首次越线时留痕，避免处理器自身刷日志。
      if (v.action === cursorGuard.CURSOR_DROP && v.reason === cursorGuard.DROP_FLOOD) {
        recordSecurityEvent('cursor-abuse', 'warn',
          cursorGuard.describeCursorReason(v.reason), originOfContents(contents));
      }
    });

    // navigation-entry-committed：地址栏据此显示最终 URL，先净化脏文本，再对历史条目
    // 提交频率（pushState 历史劫持/洪泛）做滑动窗口裁决，越限冷却并冻结地址栏刷新。
    contents.on('navigation-entry-committed', (event, url) => {
      const st = getContentsState(entryStates, contents.id, entryGuard.createEntryState);
      const v = entryGuard.decideNavigationEntry(st, url, Date.now());
      if (v.action === entryGuard.ENTRY_DROP && v.reason === entryGuard.DROP_FLOOD) {
        recordSecurityEvent('entry-flood', 'warn',
          entryGuard.describeEntryReason(v.reason), originOfContents(contents));
      }
    });

    // r33：意外原生子窗口收口。setWindowOpenHandler 恒 deny 后仍可能有少数路径真正
    // new 出原生 BrowserWindow；这里核对其 webPreferences 基线与首屏地址，提权 / 危险
    // 协议 / 开窗洪泛直接销毁，幸存的 http(s) 子窗标记为隔离并留痕。
    contents.on('did-create-window', (childWindow, details) => {
      try {
        const openerSt = getContentsState(
          childWindowStates, contents.id, childWindowGuard.createChildWindowState);
        let childContents = null;
        try {
          childContents = childWindow && childWindow.webContents ? childWindow.webContents : null;
        } catch {}
        let prefs = null;
        try {
          if (childContents && typeof childContents.getLastWebPreferences === 'function') {
            prefs = childContents.getLastWebPreferences();
          }
        } catch {}
        let childUrl = '';
        try {
          childUrl = (childContents && childContents.getURL()) || (details && details.url) || '';
        } catch {}
        const verdict = childWindowGuard.evaluateChildWindow(
          { url: childUrl, prefs, openerPresent: true }, openerSt, Date.now());
        if (verdict.action === childWindowGuard.CHILD_CLOSE) {
          recordSecurityEvent('child-window-blocked', 'warn',
            `意外子窗口已销毁（${verdict.reasons.join('；')}）: ${String(childUrl).slice(0, 200)}`,
            originOfContents(contents));
          try { childWindow.destroy(); } catch {}
          return;
        }
        if (verdict.action === childWindowGuard.CHILD_ISOLATE) {
          if (childContents) isolatedChildContents.add(childContents);
          recordSecurityEvent('child-window-blocked', 'info',
            `意外子窗口按隔离基线保留（${verdict.reasons.join('；')}）`,
            verdict.origin || originOfContents(contents));
        }
      } catch (err) {
        recordSecurityEvent('child-window-blocked', 'info',
          `子窗口守卫异常: ${String((err && err.message) || err)}`, originOfContents(contents));
      }
    });

    // r33：frame-created 观测每个框架创建。该事件无法阻止框架落地，这里负责把危险
    // 协议子框架 / 畸形 URL / iframe 爆炸统一留痕，真正的危险导航仍由 will-frame-navigate
    // 与 CSP 兜底；洪泛折叠为单条 info，避免刷爆审计。
    contents.on('frame-created', (event, frame) => {
      try {
        const st = getContentsState(frameStates, contents.id, frameGuard.createFrameState);
        const v = frameGuard.evaluateFrame(frame, st, Date.now());
        if (v.action === frameGuard.FRAME_DROP && v.reasons.length > 0) {
          const sev = v.reasons.includes('frame-flood') ? 'info' : 'warn';
          const tail = frame && frame.url ? ': ' + String(frame.url).slice(0, 200) : '';
          recordSecurityEvent('frame-blocked', sev,
            `子框架事件异常（${v.reasons.join('；')}）${tail}`,
            v.origin || originOfContents(contents));
        }
      } catch (err) {
        recordSecurityEvent('frame-blocked', 'info',
          `框架守卫异常: ${String((err && err.message) || err)}`, originOfContents(contents));
      }
    });

    // r33：screen-capture-changed 让“某个标签真的进入屏幕/窗口捕获态”可见：任何进入
    // 捕获（start / 未停先换句柄）都亮留痕，畸形 / 高频切换事件被折叠，避免网页静默录屏。
    contents.on('screen-capture-changed', (event, id, captureInfo) => {
      try {
        const st = getContentsState(captureStates, contents.id, captureGuard.createCaptureState);
        const v = captureGuard.evaluateCaptureChange(st, id, captureInfo, Date.now());
        if (v.action === captureGuard.CAPTURE_SIGNAL) {
          if (v.phase === 'started' || v.phase === 'replaced') {
            const audio = v.hasAudio ? '含音频' : '无音频';
            recordSecurityEvent('screen-capture-active', 'warn',
              v.phase === 'replaced'
                ? `屏幕捕获句柄被替换（${audio}），该标签可能持续被录制`
                : `标签进入屏幕/窗口捕获态（${audio}），请注意录屏提示`,
              originOfContents(contents));
          }
        } else if (v.action === captureGuard.CAPTURE_DROP) {
          recordSecurityEvent('screen-capture-active', 'info',
            `屏幕捕获状态事件异常已忽略（${v.reasons.join('；')}）`, originOfContents(contents));
        }
      } catch (err) {
        recordSecurityEvent('screen-capture-active', 'info',
          `捕获状态守卫异常: ${String((err && err.message) || err)}`, originOfContents(contents));
      }
    });

    // r33：devtools-opened/closed 收口调试通道本身。隔离子窗口按基线不该有 DevTools，
    // 一旦被打开立即关闭并告警；普通标签打开 DevTools 只留痕（不阻断开发者），高频
    // 开关（自动化 / 环境探测）折叠冷却。
    contents.on('devtools-opened', () => {
      try {
        const st = getContentsState(
          devtoolsSwitchStates, contents.id, devtoolsSwitchGuard.createDevtoolsState);
        const isIso = isolatedChildContents.has(contents);
        const v = devtoolsSwitchGuard.evaluateDevtoolsToggle(
          st, 'opened', { isIsolatedChild: isIso }, Date.now());
        if (v.action === devtoolsSwitchGuard.DEVTOOLS_CLOSE) {
          recordSecurityEvent('devtools-switch', 'warn',
            '按基线不应具备 DevTools 的隔离窗口被打开开发者工具，已立即关闭',
            originOfContents(contents));
          try { contents.closeDevTools(); } catch {}
        } else if (v.action === devtoolsSwitchGuard.DEVTOOLS_AUDIT) {
          recordSecurityEvent('devtools-switch', 'info',
            '该标签打开了开发者工具：请勿在控制台粘贴来源不明的代码',
            originOfContents(contents));
        }
      } catch (err) {
        recordSecurityEvent('devtools-switch', 'info',
          `DevTools 开关守卫异常: ${String((err && err.message) || err)}`, originOfContents(contents));
      }
    });
    contents.on('devtools-closed', () => {
      const st = devtoolsSwitchStates.get(contents.id);
      if (st) devtoolsSwitchGuard.evaluateDevtoolsToggle(st, 'closed', {}, Date.now());
    });

    // r33：@electron/remote 反向桥与 desktopCapturer 枚举深度防御。浏览器场景不启用
    // remote，任何一个这些事件触发都意味着提权面被打开——统一 preventDefault 拒绝，
    // 并把目标模块/全局名净化后按高危留痕；高频尝试折叠冷却。
    const installRemoteBlocker = (channel, isNamed) => {
      contents.on(channel, (event, target) => {
        try {
          const st = getContentsState(remoteStates, contents.id, remoteGuard.createRemoteState);
          const v = remoteGuard.evaluateRemoteBridge(
            { channel, target: isNamed ? target : undefined }, st, Date.now());
          event.preventDefault();
          const sev = v.reasons.includes('remote-bridge-flood') ? 'info' : 'warn';
          const tail = isNamed && v.target ? `（目标: ${v.target}）` : '';
          recordSecurityEvent('remote-bridge-blocked', sev,
            `远程桥通道 ${v.channel} 已被浏览器策略阻止${tail}`, originOfContents(contents));
        } catch (err) {
          try { event.preventDefault(); } catch {}
          recordSecurityEvent('remote-bridge-blocked', 'warn',
            `远程桥守卫异常: ${String((err && err.message) || err)}`, originOfContents(contents));
        }
      });
    };
    installRemoteBlocker(remoteGuard.REMOTE_CHANNELS.REQUIRE, true);
    installRemoteBlocker(remoteGuard.REMOTE_CHANNELS.GET_BUILTIN, true);
    installRemoteBlocker(remoteGuard.REMOTE_CHANNELS.GET_GLOBAL, true);
    installRemoteBlocker(remoteGuard.REMOTE_CHANNELS.GET_CURRENT_WINDOW, false);
    installRemoteBlocker(remoteGuard.REMOTE_CHANNELS.GET_CURRENT_WEB_CONTENTS, false);
    installRemoteBlocker(remoteGuard.REMOTE_CHANNELS.DESKTOP_CAPTURER, false);

    // r33：渲染层“直发原始 IPC”收口。正常业务只走 contextBridge 白名单 API；若网页在
    // contextIsolation 被绕过 / preload 残缺时直接 ipcRenderer.send 未授权通道，这里拦截。
    // invoke 走内部通道不触发本事件，故白名单只列 send 通道。
    contents.on('ipc-message', (event, channel, ...args) => {
      try {
        const st = getContentsState(
          ipcChannelStates, contents.id, ipcChannelGuard.createIpcChannelState);
        const v = ipcChannelGuard.evaluateIpcChannel(
          { channel, kind: ipcChannelGuard.IPC_ASYNC, argsLength: args.length },
          RAW_IPC_SEND_ALLOWED, st, Date.now());
        if (v.action === ipcChannelGuard.IPC_BLOCK) {
          event.preventDefault();
          recordSecurityEvent('raw-ipc-blocked', 'warn',
            `渲染层直发未授权/异常原始 IPC 通道 ${v.channel}（${v.reasons.join('；')}）`,
            originOfContents(contents));
        }
        const ipcPayloadAudit = securityBoundaryHub.inspectIpcRequest(args);
        if (ipcPayloadAudit.changed) {
          event.preventDefault();
          recordSecurityEvent('raw-ipc-blocked', 'warn',
            `IPC 负载结构未通过安全检查: ${securityBoundaryHub.describeFindings(ipcPayloadAudit.findings)}`,
            originOfContents(contents));
        }
      } catch (err) {
        recordSecurityEvent('raw-ipc-blocked', 'info',
          `原始 IPC 守卫异常: ${String((err && err.message) || err)}`, originOfContents(contents));
      }
    });
    // sendSync 白名单为空，任何同步直发都阻止，并回一个安全值，避免网页拿到 undefined
    // 后逻辑异常，同时杜绝同步消息阻塞主进程的拒绝服务。
    contents.on('ipc-message-sync', (event, channel, ...args) => {
      try {
        const st = getContentsState(
          ipcChannelStates, contents.id, ipcChannelGuard.createIpcChannelState);
        const v = ipcChannelGuard.evaluateIpcChannel(
          { channel, kind: ipcChannelGuard.IPC_SYNC, argsLength: args.length },
          RAW_IPC_SYNC_ALLOWED, st, Date.now());
        if (v.action === ipcChannelGuard.IPC_BLOCK) {
          event.preventDefault();
          try { event.returnValue = null; } catch {}
          recordSecurityEvent('raw-ipc-blocked', 'warn',
            `渲染层同步 IPC（sendSync）被禁止 ${v.channel}（${v.reasons.join('；')}）`,
            originOfContents(contents));
        }
      } catch (err) {
        try { event.preventDefault(); event.returnValue = null; } catch {}
        recordSecurityEvent('raw-ipc-blocked', 'warn',
          `同步 IPC 守卫异常: ${String((err && err.message) || err)}`, originOfContents(contents));
      }
    });

    // ===== r34：设备授权撤销 + 跨框架存储/缓存访问收口 =====
    // hid/serial/bluetooth 的 *-revoked 事件此前 0 监听：授权被用户收回 / 设备掉线
    // 完全无留痕，且可被“申请—掉线—再申请”抖动刷成事件洪泛。统一走 revokeGuard
    // 按 源+类别+设备 时间窗去重，仅在窗口外落一条审计。
    const handleDeviceRevoked = (kind, device) => {
      try {
        const st = getContentsState(revokeStates, contents.id, revokeGuard.createRevokeState);
        const v = revokeGuard.decideRevocation(
          st, { kind, originUrl: currentContentsUrl(), device }, Date.now());
        if (v.action === revokeGuard.ACTION_RECORD) {
          recordSecurityEvent('device-authorization-revoked', 'info',
            v.detail, v.origin || originOfContents(contents));
        }
      } catch (err) {
        recordSecurityEvent('device-authorization-revoked', 'info',
          `设备撤销守卫异常: ${String((err && err.message) || err)}`, originOfContents(contents));
      }
    };
    contents.on('hid-device-revoked', (_e, device) => {
      handleDeviceRevoked(revokeGuard.KIND_HID, device);
    });
    contents.on('serial-port-revoked', (_e, port) => {
      // serial 撤销回调给的是端口对象，可能带 portName / usbVendorId / usbProductId。
      handleDeviceRevoked(revokeGuard.KIND_SERIAL, port);
    });
    contents.on('bluetooth-device-revoked', (_e, deviceId) => {
      // 蓝牙撤销给的是 deviceId 字符串，包一层成内核期望的 device 形状。
      handleDeviceRevoked(revokeGuard.KIND_BLUETOOTH,
        typeof deviceId === 'string' ? { deviceId } : {});
    });

    // seen-session-storage-data-access / seen-cache-storage-data-access 是观测型事件
    // （不可 preventDefault）。价值在于发现“跨站子框架读写顶层存储”与高频存储事件洪泛。
    // 只在“跨源桶首次”与“窗内越限”两个有界时刻留痕，避免观测处理器自己刷爆日志。
    const handleStorageDataAccess = (kind, details) => {
      try {
        const st = getContentsState(
          storageAccessStates, contents.id, storageAccessGuard.createStorageAccessState);
        let frameUrl = '';
        try { frameUrl = details && details.frame && details.frame.url ? details.frame.url : ''; } catch {}
        const topUrl = currentContentsUrl();
        const storageType = kind === storageAccessGuard.KIND_CACHE
          ? (details && details.cacheType) : (details && details.storageType);
        const v = storageAccessGuard.decideStorageAccess(
          st,
          { kind, frameUrl, topUrl, key: details && details.key, storageType },
          Date.now());
        if (v.action !== storageAccessGuard.ACTION_REPORT) return;
        if (v.reason === 'cross-origin-storage-access') {
          const label = kind === storageAccessGuard.KIND_CACHE ? '缓存分区' : '会话存储';
          recordSecurityEvent('storage-cross-access', 'info',
            `跨站子框架访问顶层${label}：${v.frameOrigin || '未知源'} -> ${v.topOrigin || '未知源'}`,
            v.topOrigin || originOfContents(contents));
        } else if (v.reason === 'storage-access-flood') {
          recordSecurityEvent('storage-access-flood', 'warn',
            `存储访问事件高频洪泛（${kind}，窗口内 ${v.windowHits} 次）`,
            v.topOrigin || originOfContents(contents));
        }
      } catch (err) {
        recordSecurityEvent('storage-access-flood', 'info',
          `存储访问守卫异常: ${String((err && err.message) || err)}`, originOfContents(contents));
      }
    };
    contents.on('seen-session-storage-data-access', (event, details) => {
      handleStorageDataAccess(storageAccessGuard.KIND_SESSION, details);
    });
    contents.on('seen-cache-storage-data-access', (event, details) => {
      handleStorageDataAccess(storageAccessGuard.KIND_CACHE, details);
    });
  });

  return { setupGlobalWebContentsHooks };
}

module.exports = { create };
