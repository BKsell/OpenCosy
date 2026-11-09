'use strict';

let d = {};

function bindDeps(next) {
  d = next;
}

async function copyExtensionToStorage(sourcePath, extensionId) {
  const targetRoot = d.extensionStore.resolveExtensionDir(d.extensionsPath, extensionId);
  if (!targetRoot) return { ok: false, reason: 'invalid-extension-id' };
  const budget = d.extensionStore.createCopyBudget();

  async function walk(srcDir, depth, relSegments) {
    const files = await d.fs.readdir(srcDir);
    for (const file of files) {
      const srcFile = d.path.join(srcDir, file);
      let stat;
      try {
        stat = await d.fs.lstat(srcFile);
      } catch {
        return { ok: false, reason: 'stat-failed' };
      }
      const verdict = d.extensionStore.classifyCopyEntry({
        name: file,
        symlink: stat.isSymbolicLink(),
        directory: stat.isDirectory(),
        size: stat.size,
      }, depth, budget);

      if (verdict.action === d.extensionStore.COPY_SKIP) continue;
      if (verdict.action === d.extensionStore.COPY_REJECT) {
        return { ok: false, reason: verdict.reason };
      }
      const destFile = d.extensionStore.resolveWithinRoot.apply(
        null, [targetRoot].concat(relSegments, [file]));
      if (!destFile) return { ok: false, reason: 'target-outside-root' };

      if (verdict.action === d.extensionStore.COPY_ACCEPT_DIR) {
        await d.fs.mkdir(destFile, { recursive: true });
        const sub = await walk(srcFile, depth + 1, relSegments.concat([file]));
        if (!sub.ok) return sub;
      } else {
        await d.fs.copyFile(srcFile, destFile);
      }
    }
    return { ok: true };
  }

  try {
    await d.fs.mkdir(targetRoot, { recursive: true });
    const result = await walk(sourcePath, 1, []);
    if (!result.ok) {
      await d.fs.rm(targetRoot, { recursive: true, force: true }).catch(() => {});
    }
    return result;
  } catch (e) {
    console.error('复制插件失败:', e);
    await d.fs.rm(targetRoot, { recursive: true, force: true }).catch(() => {});
    return { ok: false, reason: 'copy-exception' };
  }
}

async function validateExtensionFolder(folderPath) {
  try {
    const manifestPath = d.path.join(folderPath, 'manifest.json');
    if (!d.fsSync.existsSync(manifestPath)) return { valid: false, error: '文件夹中未找到manifest.json文件' };
    const manifest = JSON.parse(await d.fs.readFile(manifestPath, 'utf8'));
    if (!manifest.name) return { valid: false, error: 'manifest.json中缺少name字段' };
    if (!manifest.version) return { valid: false, error: 'manifest.json中缺少version字段' };
    if (!manifest.manifest_version) return { valid: false, error: 'manifest_version字段缺失' };
    if (manifest.permissions && Array.isArray(manifest.permissions)) {
      const dangerousPermissions = ['<all_urls>', 'tabs', 'history', 'bookmarks', 'cookies', 'webRequest', 'webRequestBlocking', 'proxy', 'management', 'debugger', 'nativeMessaging'];
      if (manifest.permissions.some(p => dangerousPermissions.includes(p))) {
        const requested = manifest.permissions
          .filter(p => dangerousPermissions.includes(p))
          .slice(0, 8).join(', ');
        d.recordSecurityEvent('extension-blocked', 'critical',
          `扩展 ${manifest.name || '(未命名)'} 请求危险权限被拒绝: ${requested}`,
          `extension:${manifestPath || ''}`);
        return { valid: false, error: '插件请求了危险权限，已被拒绝加载' };
      }
    }
    return { valid: true, manifest };
  } catch (e) {
    d.recordSecurityEvent('extension-blocked', 'warn',
      `扩展 manifest.json 读取或解析失败: ${e && e.message ? e.message : e}`,
      `extension:${folderPath || ''}`);
    return { valid: false, error: '读取manifest.json失败: ' + e.message };
  }
}

module.exports = { copyExtensionToStorage, validateExtensionFolder, bindDeps };
