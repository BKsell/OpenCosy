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
  'close-current-tab',
  'find-in-page',
  'stop-find',
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
  'get-current-tab',
  'get-all-tabs',
  'add-extension',
  'get-extensions',
  'toggle-extension',
  'remove-extension',
  'browse-folder',
  'get-bookmarks',
  'get-history',
  'clear-history',
  'clear-browsing-data',
]);

// 接收方向白名单：main -> renderer
const allowedOnChannels = new Set([
  'tab-created',
  'tab-updated',
  'tab-loading',
  'tab-switched',
  'tab-closed',
  'tab-history-changed',
  'html-fullscreen-changed',
  'update-theme-color',
  'settings-loaded',
  'download-status-changed',
  'download-progress',
  'download-complete',
  'download-error',
  'download-started',
  'downloads-list',
  'download-removed',
  'downloads-cleared',
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
  'show-clear-data-dialog',
  'toggle-bookmarks-bar',
  'network-status-changed',
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
