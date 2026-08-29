const { contextBridge, ipcRenderer } = require('electron');

const allowedChannels = new Set([
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
  'create-tab',
]);

contextBridge.exposeInMainWorld('electronAPI', {
  minimize: () => ipcRenderer.send('window-control', 'minimize'),
  maximize: () => ipcRenderer.send('window-control', 'maximize'),
  close: () => ipcRenderer.send('window-control', 'close'),
  send: (channel, data) => {
    if (allowedChannels.has(channel)) {
      ipcRenderer.send(channel, data);
    }
  },
  invoke: (channel, data) => {
    const allowedInvokeChannels = new Set([
      'create-tab',
      'switch-tab',
      'close-tab',
      'navigate-tab',
      'get-current-tab',
      'get-all-tabs',
      'add-extension',
      'get-extensions',
      'toggle-extension',
      'remove-extension',
      'browse-folder',
    ]);
    if (allowedInvokeChannels.has(channel)) {
      return ipcRenderer.invoke(channel, data);
    }
    return Promise.reject(new Error('Channel not allowed'));
  },
  on: (channel, callback) => {
    const allowedOnChannels = new Set([
      'tab-created',
      'tab-updated',
      'tab-loading',
      'tab-switched',
      'tab-closed',
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
    ]);
    if (allowedOnChannels.has(channel)) {
      ipcRenderer.on(channel, (event, ...args) => callback(...args));
    }
  },
});
