'use strict';

const { registerTabMenuIpc } = require('./cosyipctabmenuipc');

let d = {};

function bindDeps(x) {
  d = x;
}

function registerExtensionIpc() {
d.ipcMain.handle('add-extension', async (event, folderPath) => {
  if (!d.isMainSender(event)) return { success: false, error: 'Unauthorized' };
  try {
    const validation = await d.validateExtensionFolder(folderPath);
    if (!validation.valid) return { success: false, error: validation.error };
    const { manifest } = validation;
    const extensionId = d.extensionStore.buildExtensionId(manifest.name, manifest.version);
    if (!extensionId) return { success: false, error: '插件名称或版本不合法，无法生成安全ID' };
    const config = await d.readExtensionsConfig();
    if (config.extensions.find(ext => ext.id === extensionId)) return { success: false, error: '该插件已存在' };
    const copyResult = await d.copyExtensionToStorage(folderPath, extensionId);
    if (!copyResult.ok) return { success: false, error: '复制插件文件失败（' + copyResult.reason + '）' };
    let iconPath = '';
    if (manifest.icons) {
      const iconSizes = Object.keys(manifest.icons).sort((a, b) => parseInt(b) - parseInt(a));
      if (iconSizes.length > 0) {
        const iconName = manifest.icons[iconSizes[0]];
        if (d.isSafeEntryName(iconName)) {
          iconPath = d.extensionStore.resolveWithinRoot(d.extensionsPath, extensionId, iconName) || '';
        }
      }
    }
    const extensionDir = d.extensionStore.resolveExtensionDir(d.extensionsPath, extensionId);
    const newExtension = {
      id: extensionId, name: manifest.name, version: manifest.version,
      description: manifest.description || '', icon: iconPath,
      path: extensionDir || '', enabled: true, addedDate: new Date().toISOString()
    };
    config.extensions.push(newExtension);
    const saveSuccess = await d.saveExtensionsConfig(config);
    if (!saveSuccess) return { success: false, error: '保存配置失败' };
    return { success: true, extension: newExtension };
  } catch (e) { return { success: false, error: e.message }; }
});

d.ipcMain.handle('get-extensions', async (event) => {
  if (!d.isMainSender(event)) return { success: false, error: 'Unauthorized', extensions: [] };
  try {
    const config = await d.readExtensionsConfig();
    return { success: true, extensions: config.extensions };
  } catch (e) { return { success: false, error: e.message, extensions: [] }; }
});

d.ipcMain.handle('toggle-extension', async (event, { id, enabled }) => {
  if (!d.isMainSender(event)) return { success: false, error: 'Unauthorized' };
  try {
    const config = await d.readExtensionsConfig();
    const extension = config.extensions.find(ext => ext.id === id);
    if (!extension) return { success: false, error: '插件未找到' };
    extension.enabled = enabled;
    const saveSuccess = await d.saveExtensionsConfig(config);
    if (!saveSuccess) return { success: false, error: '保存配置失败' };
    return { success: true };
  } catch (e) { return { success: false, error: e.message }; }
});

d.ipcMain.handle('remove-extension', async (event, id) => {
  if (!d.isMainSender(event)) return { success: false, error: 'Unauthorized' };
  try {
    const config = await d.readExtensionsConfig();
    const extensionIndex = config.extensions.findIndex(ext => ext.id === id);
    if (extensionIndex === -1) return { success: false, error: '插件未找到' };
    await d.unloadExtension(id);
    // 递归 rm 前必须把目录收口到扩展根之内：配置若被塞成 id="../AppData"，旧实现
    // path.join 后会递归删除扩展目录之外的内容。越界直接拒绝删除。
    const extensionPath = d.extensionStore.resolveExtensionDir(d.extensionsPath, id);
    if (!extensionPath) {
      d.recordSecurityEvent('extension-blocked', 'warn',
        `拒绝删除越界插件目录（id=${id}）`, '');
      return { success: false, error: '插件目录不合法' };
    }
    if (d.fsSync.existsSync(extensionPath)) await d.fs.rm(extensionPath, { recursive: true, force: true });
    config.extensions.splice(extensionIndex, 1);
    const saveSuccess = await d.saveExtensionsConfig(config);
    if (!saveSuccess) return { success: false, error: '保存配置失败' };
    return { success: true };
  } catch (e) { return { success: false, error: e.message }; }
});

d.ipcMain.handle('browse-folder', async (event) => {
  if (!d.isMainSender(event)) return { success: false, error: 'Unauthorized' };
  try {
    const result = await d.dialog.showOpenDialog(d.mainWindow, { title: '选择插件文件夹', properties: ['openDirectory'] });
    if (!result.canceled && result.filePaths.length > 0) return { success: true, path: result.filePaths[0] };
    return { success: false, error: '用户取消选择' };
  } catch (e) { return { success: false, error: e.message }; }
});

d.ipcMain.on('show-context-menu', (event, data) => {
  if (!d.isMainSender(event)) return;
  const payload = data && typeof data === 'object' ? data : {};
  const menuType = payload.menuType === 'selection' ? 'selection' : 'default';
  const selectedText = typeof payload.selectedText === 'string' ? payload.selectedText.slice(0, 256) : '';
  const menu = d.createContextMenu(menuType, selectedText);
  if (!d.mainWindow || d.mainWindow.isDestroyed()) return;
  menu.popup({ window: d.mainWindow });
});

// ===== 标签页右键菜单（原生 Tab 菜单）=====
// 渲染层在标签元素上右键时只上报内部 tabId；这里基于主进程维护的 tab 状态构建
// 原生菜单。菜单项的 URL / 标题全部来自本机 tabs 数据（非网页注入），复制走
// clipboard 仅写入受控文本，杜绝自绘菜单的样式/事件注入面。
  registerTabMenuIpc(d);
}

module.exports = { bindDeps, registerExtensionIpc };
