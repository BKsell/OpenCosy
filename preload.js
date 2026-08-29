const { contextBridge, ipcRenderer } = require('electron');

// 安全地暴露 ipcRenderer 给渲染进程
// 只暴露必要的方法，避免直接暴露 ipcRenderer 对象
contextBridge.exposeInMainWorld('electron', {
  ipcRenderer: {
    invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args),
    send: (channel, ...args) => ipcRenderer.send(channel, ...args),
    on: (channel, listener) => {
      // 只允许监听白名单中的频道，防止恶意页面监听敏感事件
      const allowedChannels = [
        'tab-switched', 'tab-created', 'tab-closed', 'downloadProgress',
        'downloadListUpdated', 'download-completed', 'serverLog', 'serverStatus',
        'serverReady', 'msLoginProgress', 'msLoginSuccess', 'msLoginError',
        'settings-updated', 'extension-loaded', 'url-changed', 'title-changed',
        'favicon-updated', 'context-menu', 'new-tab-request', 'will-navigate'
      ];
      if (allowedChannels.includes(channel)) {
        ipcRenderer.on(channel, listener);
      }
    },
    removeListener: (channel, listener) => ipcRenderer.removeListener(channel, listener),
    removeAllListeners: (channel) => ipcRenderer.removeAllListeners(channel),
  },
  // 暴露平台信息
  platform: process.platform,
  versions: process.versions,
});
