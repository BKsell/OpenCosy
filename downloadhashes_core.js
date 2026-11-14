const { app, dialog } = require('electron');
const path = require('path');
const { clearLedgerStore } = require('./ledgerclear_core');
const fsSync = require('fs');
const urlResolve = require('./urlresolve_core');

const {
  MAX_DOWNLOAD_HASH_RECORDS,
  downloadHashChain,
  downloadHashStorePath,
  getMainWindow,
  hashFileSha256,
  loadDownloadHashes,
  persistDownloadHashes,
  sendToRenderer,
  upsertDownloadHashRecord
} = require('./downloadhashes_store_core');
const downloadHashStore = require('./downloadhashes_store_core');

// queueDownloadHashing 把一次下载完成事件排进串行摘要链。
// 摘要是附加能力，任何失败都静默跳过，绝不能影响下载本身的可用性。
function queueDownloadHashing(task) {
  downloadHashChain = downloadHashChain.then(async () => {
    try {
      const { sha256, size } = await hashFileSha256(task.savePath);
      const host = urlResolve.safeHost(task.url);
      const record = {
        id: String(task.id),
        time: Date.now(),
        filename: String(task.filename || '').slice(0, 255) || 'download',
        size,
        sha256,
        host,
      };
      upsertDownloadHashRecord(record);
      sendToRenderer('download-hashed', record);
    } catch (e) {
      console.log('[download-hash] 摘要失败，已跳过:', String(e && e.message || e));
    }
  });
  return downloadHashChain;
}

function listDownloadHashes(limit = 200) {
  loadDownloadHashes();
  const n = Math.max(1, Math.min(Number(limit) || 200, MAX_DOWNLOAD_HASH_RECORDS));
  return downloadHashRecords.slice(-n).reverse().map(r => ({ ...r }));
}

function removeDownloadHashRecord(id) {
  loadDownloadHashes();
  const idx = downloadHashRecords.findIndex(r => r.id === String(id));
  if (idx < 0) return false;
  downloadHashRecords.splice(idx, 1);
  persistDownloadHashes();
  return true;
}

function clearDownloadHashes() {
  return clearLedgerStore(loadDownloadHashes, downloadHashRecords, downloadHashStorePath, persistDownloadHashes);
}

// normalizeExpectedHash 校验用户粘贴的期望摘要：支持 64 位 hex，
// 兼容大小写与首尾空白；其它输入返回空串，由调用方判定为非法。
function normalizeExpectedHash(input) {
  const s = String(input || '').trim().toLowerCase();
  return /^[a-f0-9]{64}$/.test(s) ? s : '';
}

function verifyDownloadHashById(id, expected) {
  loadDownloadHashes();
  const want = normalizeExpectedHash(expected);
  if (!want) return { ok: false, reason: 'invalid-expected' };
  const rec = downloadHashRecords.find(r => r.id === String(id));
  if (!rec) return { ok: false, reason: 'not-found' };
  // 常量时间比较，避免把摘要比对变成时序侧信道。
  let acc = 0;
  for (let i = 0; i < 64; i++) acc |= rec.sha256.charCodeAt(i) ^ want.charCodeAt(i);
  const match = acc === 0;
  return { ok: match, match, filename: rec.filename, actual: rec.sha256 };
}

// hashLocalFileViaDialog 让用户在 cosy://hashes 页面选择任意本地文件计算
// 摘要，用于校验从别处拷贝来的安装包。只回传文件名 / 大小 / 摘要，不回传路径。
async function hashLocalFileViaDialog() {
  const choice = await dialog.showOpenDialog(getMainWindow(), {
    title: '选择要计算 SHA-256 的文件',
    properties: ['openFile']
  });
  if (choice.canceled || !choice.filePaths || !choice.filePaths.length) {
    return { ok: false, reason: 'canceled' };
  }
  const filePath = choice.filePaths[0];
  let digest;
  try {
    digest = await hashFileSha256(filePath);
  } catch (e) {
    return { ok: false, reason: String(e && e.message || e) };
  }
  return { ok: true, filename: path.basename(filePath), size: digest.size, sha256: digest.sha256 };
}

module.exports = {
  bindRendererNotifier: downloadHashStore.bindRendererNotifier,
  bindWindowHost: downloadHashStore.bindWindowHost,
  clearDownloadHashes,
  hashLocalFileViaDialog,
  listDownloadHashes,
  normalizeExpectedHash,
  queueDownloadHashing,
  removeDownloadHashRecord,
  verifyDownloadHashById,
};
