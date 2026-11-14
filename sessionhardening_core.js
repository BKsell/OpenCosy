'use strict';

const sessionGuard = require('./sessionguard_core');

function setupExtraSessionHardening(ctx) {
  const {
    app,
    applyOutboundHeaderHardening,
    applyWebRequestFiltering,
    attachDownloadManager,
    downloads: readDownloads,
    recordSecurityEvent,
    session,
    sessionGuardState,
    setupSecurityHeaders,
    urlResolve,
    webContents,
  } = ctx;
  const originOfPermissionRequest = (webContents) => {
    if (!webContents || typeof webContents.getURL !== 'function') return '';
    return urlResolve.safeOrigin(webContents.getURL(), '');
  };

  // 出向请求头与 onBeforeRequest 过滤统一复用模块级共享内核
  // applyOutboundHeaderHardening / applyWebRequestFiltering，确保隔离 / 访客 /
  // 非法分区会话与默认会话行为一致（tracker、ping、PNA、混合内容、HTTPS-only、
  // 追踪参数剥离、Client Hints / 广告头清洗全部生效），仅关闭默认会话的聚合计数。

  // applyIncomingResponseHardening：让隔离 / 访客会话与 defaultSession 走同一套
  // 入向响应头加固（nosniff / XFO / Referrer-Policy / Permissions-Policy 画中画 /
  // HSTS / 本地页 CSP + COOP/COEP/CORP / Cookie 收口），补齐此前只挂出向头的纵深缺口。
  // 非默认会话不重复记安全头评级（评级只在主会话聚合，避免分区会话重复计数）。
  const applyIncomingResponseHardening = (ses) => {
    try {
      ses.webRequest.onHeadersReceived((details, callback) => {
        const headers = hardenResponseHeaders(details.responseHeaders, details, { grade: false });
        callback({ responseHeaders: headers });
      });
    } catch {}
  };

  app.on('session-created', (ses) => {
    let partition = '';
    try { partition = typeof ses.getStoragePath === 'function' ? '' : (ses.partition || ''); } catch {}
    // session 对象未必直接暴露 partition；sessionGuard 只需要分区串。取不到时按空串，
    // 但 defaultSession 已被单独加固并占位，真正落到这里的空串会话仍按最保守基线处理。
    let decision;
    try {
      decision = sessionGuard.decideSessionHarden(sessionGuardState, { partition });
    } catch {
      decision = null;
    }

    // defaultSession 已加固，去重命中后不重复注册。
    if (decision && decision.alreadyHardened) return;

    if (decision && !decision.shouldHarden) {
      // 分区串非法：不留裸奔会话，仍强制默认拒绝，并留一条独立事件提示分区异常。
      try {
        ses.setPermissionRequestHandler((wc, _permission, cb) => {
          try { cb(false); } catch {}
        });
        if (typeof ses.setPermissionCheckHandler === 'function') {
          ses.setPermissionCheckHandler(() => false);
        }
        if (typeof ses.setDevicePermissionHandler === 'function') {
          ses.setDevicePermissionHandler(() => false);
        }
      } catch {}
      applyOutboundHeaderHardening(ses, { recordFp: false });
      applyWebRequestFiltering(ses, { logRequests: false });
      applyIncomingResponseHardening(ses);
      // 即便分区串非法，其下载仍会在该 session 上触发，同样挂下载保护，杜绝借
      // 异常分区绕过文件名净化 / 危险类型确认 / MOTW。
      try { attachDownloadManager(ses); } catch {}
      recordSecurityEvent('session-partition-rejected', 'warn',
        `检测到非法会话分区（${decision.reason}），已对该会话强制默认拒绝`, '');
      return;
    }

    // 合法的非默认会话：全套默认拒绝基线 + 出向隐私头。
    try {
      ses.setPermissionRequestHandler((webContents, permission, callback) => {
        const origin = originOfPermissionRequest(webContents);
        recordSecurityEvent('permission-blocked', 'info',
          `隔离/访客会话中的权限请求已默认拒绝: ${permission}`, origin);
        try { callback(false); } catch {}
      });
      if (typeof ses.setPermissionCheckHandler === 'function') {
        ses.setPermissionCheckHandler(() => false);
      }
      if (typeof ses.setDevicePermissionHandler === 'function') {
        ses.setDevicePermissionHandler((details) => {
          const origin = urlResolve.safeOrigin((details && details.origin) || '');
          recordSecurityEvent('device-permission-blocked', 'info',
            `隔离/访客会话中的设备选择已默认拒绝（${details && details.permissionType ? details.permissionType : '未知'}）`,
            origin);
          return false;
        });
      }
    } catch {}
    applyOutboundHeaderHardening(ses, { recordFp: false });
    applyWebRequestFiltering(ses, { logRequests: false });
    applyIncomingResponseHardening(ses);
    // 隔离 / 访客会话的下载挂同一套保护：文件名穿越净化、可执行 / 伪装确认、
    // 唯一保存路径与 MOTW 全部生效，台账仍聚合到模块级 downloads[]。
    try { attachDownloadManager(ses); } catch {}

    const persist = decision && decision.classification && decision.classification.persist;
    recordSecurityEvent('session-hardened', 'info',
      `新建${persist ? '持久' : '临时'}会话已套用默认拒绝权限/设备策略、出向隐私头与入向响应头加固`, '');
  });

  // 先把 defaultSession 标记为“已加固”，真正的处理器由 setupPermissionHandlers /
  // setupSecurityHeaders 注册；这样 session-created 即便为默认会话触发也会被去重跳过。
  try {
    sessionGuard.decideSessionHarden(sessionGuardState, { partition: '' });
  } catch {}
}

module.exports = { setupExtraSessionHardening };
