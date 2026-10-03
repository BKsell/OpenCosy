const { contextBridge, ipcRenderer } = require('electron');

// 发送方向白名单：renderer -> main
const allowedSendChannels = new Set([
  'window-control',
  'toggle-tabbar-collapse',
  'navigate-to-url',
  'save-settings',
  'update-theme-color',
  'get-settings',
  'export-config',
  'show-context-menu',
  'show-more-options-menu',
  'get-download-info',
  'start-download',
  'show-save-dialog',
  'get-downloads',
  'pause-download',
  'resume-download',
  'cancel-download',
  'retry-download',
  'remove-download',
  'open-file',
  'open-folder',
  'clear-downloads',
  'shelf-show-all',
  'close-current-tab',
  'find-in-page',
  'stop-find',
  'reload-tab-by-id',
  'reopen-tab-url',
  'reset-trackers',
  'report-csp-violation',
]);

// 调用方向白名单：renderer -> main -> renderer
const allowedInvokeChannels = new Set([
  'create-tab',
  'switch-tab',
  'close-tab',
  'navigate-tab',
  'navigate-back',
  'navigate-forward',
  'reload-tab',
  'stop-loading',
  'duplicate-tab',
  'reopen-closed-tab',
  'set-tab-muted',
  'get-current-tab',
  'get-all-tabs',
  'add-extension',
  'get-extensions',
  'toggle-extension',
  'remove-extension',
  'browse-folder',
  'get-bookmarks',
  'export-bookmarks',
  'import-bookmarks',
  'get-history',
  'clear-history',
  'clear-browsing-data',
  'get-https-only',
  'get-network-status',
  'open-external-url',
  'permission-response',
  'set-zoom',
  'get-download-shelf',
  'clear-site-data',
  'list-site-data',
  'get-site-cookies',
  'delete-site-cookie',
  'delete-site-cookies',
  'clear-site-storage',
  'list-permission-decisions',
  'reset-permission-decision',
  'clear-permission-decisions',
  'get-protocol-decisions',
  'clear-protocol-decision',
  'list-security-events',
  'clear-security-events',
  'list-csp-reports',
  'clear-csp-reports',
  'remove-csp-report',
  'get-csp-report-stats',
  'list-header-grades',
  'clear-header-grades',
  'get-header-grade-stats',
  'list-request-log',
  'clear-request-log',
  'get-request-log-stats',
  'list-brand-spoofs',
  'clear-brand-spoofs',
  'get-brand-spoof-stats',
  'approve-cert-exception',
  'list-cert-exceptions',
  'remove-cert-exception',
  'clear-cert-exceptions',
  'get-cert-exception-stats',
  'list-download-hashes',
  'verify-download-hash',
  'remove-download-hash',
  'clear-download-hashes',
  'hash-local-file',
  'print-current-tab',
  'get-search-suggestions',
  'discard-tab',
  'discard-background-tabs',
  'get-memory-saver',
  'get-trackers',
  'get-spellcheck-info',
  'submit-network-auth',
  'cancel-network-auth',
  'choose-client-cert',
  'cancel-client-cert',
  'list-remembered-certs',
  'forget-remembered-cert',
  'clear-remembered-certs',
  'get-auth-stats',
  'list-cookie-hardening',
  'get-cookie-hardening-stats',
  'clear-cookie-hardening',
  'list-pna-blocks',
  'get-pna-block-stats',
  'clear-pna-blocks',
  'list-fingerprint-entries',
  'get-fingerprint-stats',
  'clear-fingerprint-entries',
  'get-doh-status',
  'clear-doh-events',
  'list-download-risks',
  'clear-download-risks',
  'clean-share-url',
]);

// 接收方向白名单：main -> renderer
const allowedOnChannels = new Set([
  'tab-created',
  'tab-updated',
  'tab-loading',
  'tab-switched',
  'tab-closed',
  'tab-history-changed',
  'tab-audio-changed',
  'popup-blocked',
  'tab-crashed',
  'tab-discarded',
  'tab-reloaded',
  'permission-request',
  'html-fullscreen-changed',
  'update-theme-color',
  'settings-loaded',
  'download-status-changed',
  'download-progress',
  'download-complete',
  'download-error',
  'download-started',
  'downloads-list',
  'download-shelf',
  'download-removed',
  'downloads-cleared',
  'download-hashed',
  'clear-downloads-success',
  'export-config-success',
  'export-config-canceled',
  'export-config-error',
  'settings-saved',
  'download-info',
  'bookmarks-updated',
  'show-toast',
  'focus-address-bar',
  'show-history',
  'show-find-bar',
  'found-in-page-result',
  'show-clear-data-dialog',
  'toggle-bookmarks-bar',
  'network-status-changed',
  'native-theme-changed',
  'zoom-level-changed',
  'renderer-gone',
  'renderer-unresponsive',
  'renderer-responsive',
  'gpu-process-gone',
  'trackers-blocked',
  'spoof-warning',
  'brand-spoof-warning',
  'brand-spoof-updated',
  'phish-url-warning',
  'csp-report-added',
  'header-grade-updated',
  'request-log-updated',
  'cert-error-blocked',
  'cert-exception-updated',
  'network-auth-required',
  'client-cert-required',
  'client-cert-choices-updated',
  'cookie-hardening-updated',
  'pna-blocked-updated',
  'fingerprint-blocked-updated',
]);

// sanitizeArg 过滤掉 renderer 传入的可疑对象：只保留 JSON 可序列化的纯数据，
// 防止通过 prototype / getter 之类把 main 进程的对象引用偷渡过去。
function sanitizeArg(value, depth = 0) {
  if (value === null || value === undefined) return value;
  if (depth > 4) return undefined;
  const t = typeof value;
  if (t === 'string' || t === 'number' || t === 'boolean') return value;
  if (Array.isArray(value)) {
    return value
      .slice(0, 64)
      .map(v => sanitizeArg(v, depth + 1))
      .filter(v => v !== undefined);
  }
  if (t === 'object') {
    const out = {};
    for (const key of Object.keys(value).slice(0, 64)) {
      if (key.startsWith('__')) continue; // 跳过 electron 内部符号
      const v = sanitizeArg(value[key], depth + 1);
      if (v !== undefined) out[key] = v;
    }
    return out;
  }
  // function / symbol / bigint 一律拒绝
  return undefined;
}

// 渲染端暴露面收口（纵深第一层，主进程 ipcguard 是第二层）。
// 这一份 preload 同时被两类上下文注入：主窗口外壳（file: 的 index.html）、标签
// WebContentsView（既承载 cosy: 内置页，也承载任意远程 http(s) 网页）。历史上远程
// 网页也拿到了下面整套 electronAPI（约 130 个 invoke/send 通道），任何被访问的恶意
// 站点都能尝试调用“清除浏览数据 / 导出配置 / 放行证书例外”等特权方法。
// 这里按文档协议在渲染端就不注入 API：只有浏览器自己的 file:/cosy: 文档拿得到，
// 远程页与 data/blob/about 等不可信文档下 window.electronAPI 根本不存在。
// 判定与 preloadpolicy.js 保持同一口径；preload 在 sandbox 内不能 require 本地模块，
// 而 location.protocol 已由浏览器规范化为小写带冒号，直接比较即可，无需自己解析 URL。
const docProtocol = (typeof location !== 'undefined' && location.protocol ? String(location.protocol) : '').toLowerCase();
const isInternalDocument = docProtocol === 'file:' || docProtocol === 'cosy:';

if (isInternalDocument) {
  contextBridge.exposeInMainWorld('electronAPI', {
    minimize: () => ipcRenderer.send('window-control', 'minimize'),
    maximize: () => ipcRenderer.send('window-control', 'maximize'),
    close: () => ipcRenderer.send('window-control', 'close'),

    send: (channel, data) => {
      if (typeof channel !== 'string' || !allowedSendChannels.has(channel)) return;
      ipcRenderer.send(channel, sanitizeArg(data));
    },

    invoke: (channel, data) => {
      if (typeof channel !== 'string' || !allowedInvokeChannels.has(channel)) {
        return Promise.reject(new Error('Channel not allowed'));
      }
      return ipcRenderer.invoke(channel, sanitizeArg(data));
    },

    on: (channel, callback) => {
      if (typeof channel !== 'string' || !allowedOnChannels.has(channel)) {
        return () => {};
      }
      if (typeof callback !== 'function') return () => {};
      const listener = (_event, ...args) => callback(...args.map(a => sanitizeArg(a)));
      ipcRenderer.on(channel, listener);
      return () => ipcRenderer.removeListener(channel, listener);
    },
  });
}
// 非内部文档：显式不暴露 electronAPI。这里不抛错、不占位，避免网站靠探测
// window.electronAPI 的存在与否判断浏览器指纹；主进程守卫仍会拒绝任何越权 IPC。

// 所有内部页面共用的 CSP 违规上报。Chromium 在内容被 CSP 拦截时会向 document
// 派发 securitypolicyviolation 事件；isolated world 里挂的捕获监听同样收得到。
// 这里只做"搬运"，来源判定（帧地址是否 cosy://）与限流全部在主进程完成，
// renderer 自报的 documentURI 不会被采信。字段先在本地限长，减少 IPC 负担。
(function installCspReporter() {
  const FIELD_LIMIT = 300;
  const clip = v => {
    const s = String(v == null ? '' : v);
    return s.length > FIELD_LIMIT ? s.slice(0, FIELD_LIMIT) : s;
  };
  document.addEventListener('securitypolicyviolation', event => {
    try {
      const report = {
        directive: clip(event.effectiveDirective || event.violatedDirective || ''),
        blockedUri: clip(event.blockedURI || ''),
        sourceFile: clip(event.sourceFile || ''),
        lineNumber: Number(event.lineNumber) || 0,
        columnNumber: Number(event.columnNumber) || 0,
        disposition: event.disposition === 'report' ? 'report' : 'enforce',
      };
      ipcRenderer.send('report-csp-violation', report);
    } catch {}
  }, true);
})();
