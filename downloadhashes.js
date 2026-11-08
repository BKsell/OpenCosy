const { app, dialog } = require('electron');
const path = require('path');
const fsSync = require('fs');
const nodeCrypto = require('crypto');
const ledgerStore = require('./ledgerstore');
const urlResolve = require('./urlresolve');

let sendToRenderer = () => {};
let getMainWindow = () => null;

function bindRendererNotifier(fn) {
  if (typeof fn === 'function') sendToRenderer = fn;
}

function bindWindowHost(fn) {
  if (typeof fn === 'function') getMainWindow = fn;
}

// ===== 下载完整性校验（download-hashes.json / cosy://hashes）=====
// Electron 的下载项只保证"字节传完了"，不保证字节没被中间人 / 镜像污染。
// 现代浏览器在"显示下载文件的校验和"这件事上普遍缺位：用户从第三方站下了
// 安装包后想核对官方公布的 SHA-256，只能自己翻 certutil。这里在每次下载
// 完成后异步流式计算 SHA-256（不占大内存），登记到本机台账，并在
// cosy://hashes 页面提供一键比对 + 任意本地文件校验。
//
// 设计约束：
//  - 串行队列：多个大文件同时下完时顺序摘要，避免把磁盘 IO 打满；
//  - 只跟普通文件，拒绝符号链接，防止摘要时被人换掉路径；
//  - 体积上限 512 GiB——正常下载永远碰不到，只有"恶意/失控的超大文件
//    拖死磁盘"时才触发；
//  - 台账只记文件名与来源主机，不记完整本地路径，减少隐私落盘。
const downloadHashStorePath = path.join(app.getPath('userData'), 'download-hashes.json');
const MAX_DOWNLOAD_HASH_RECORDS = 500;
const MAX_HASHABLE_DOWNLOAD_BYTES = 512 << 30; // 512 GiB
const HASH_READ_CHUNK = 1024 * 1024;           // 1 MiB 读取块

const downloadHashRecords = [];
let downloadHashesLoaded = false;
let downloadHashSaveTimer = null;
let downloadHashChain = Promise.resolve();

function loadDownloadHashes() {
  if (downloadHashesLoaded) return;
  downloadHashesLoaded = true;
  try {
    const data = ledgerStore.readJSONStore(downloadHashStorePath, {});
    const entries = Array.isArray(data && data.records) ? data.records : null;
    if (!entries) return;
    for (const r of entries) {
      if (!r || typeof r !== 'object') continue;
      if (typeof r.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(r.sha256)) continue;
      if (typeof r.filename !== 'string' || !r.filename) continue;
      downloadHashRecords.push({
        id: String(r.id || ''),
        time: Number(r.time) || Date.now(),
        filename: r.filename.slice(0, 255),
        size: Number.isFinite(Number(r.size)) ? Number(r.size) : 0,
        sha256: r.sha256,
        host: typeof r.host === 'string' ? r.host.slice(0, 255) : '',
      });
      if (downloadHashRecords.length >= MAX_DOWNLOAD_HASH_RECORDS) break;
    }
  } catch {}
}

function persistDownloadHashes() {
  if (downloadHashSaveTimer) clearTimeout(downloadHashSaveTimer);
  downloadHashSaveTimer = setTimeout(() => {
    try {
      ledgerStore.writeJSONStore(downloadHashStorePath, { version: 1, records: downloadHashRecords });
    } catch {}
  }, 300);
}

// hashFileSha256 以 1 MiB 流式块计算摘要，返回 { sha256, size }。
// 路径必须是普通文件；不存在 / 是符号链接 / 超体积上限一律拒绝。
function hashFileSha256(filePath) {
  return new Promise((resolve, reject) => {
    let fd;
    try {
      fd = fsSync.openSync(filePath, fsSync.constants.O_RDONLY | (fsSync.constants.O_NOFOLLOW || 0));
    } catch (e) { reject(e); return; }
    let stat;
    try {
      stat = fsSync.fstatSync(fd);
    } catch (e) {
      try { fsSync.closeSync(fd); } catch {}
      reject(e);
      return;
    }
    if (!stat.isFile()) {
      try { fsSync.closeSync(fd); } catch {}
      reject(new Error('目标不是普通文件（拒绝摘要符号链接或特殊文件）'));
      return;
    }
    if (stat.size > MAX_HASHABLE_DOWNLOAD_BYTES) {
      try { fsSync.closeSync(fd); } catch {}
      reject(new Error('文件体积超过摘要安全上限'));
      return;
    }
    const hash = nodeCrypto.createHash('sha256');
    const input = fsSync.createReadStream('', { fd, highWaterMark: HASH_READ_CHUNK, autoClose: true });
    let size = 0;
    input.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_HASHABLE_DOWNLOAD_BYTES) {
        input.destroy(new Error('文件体积超过摘要安全上限'));
        return;
      }
      hash.update(chunk);
    });
    input.on('end', () => resolve({ sha256: hash.digest('hex'), size }));
    input.on('error', reject);
  });
}

function upsertDownloadHashRecord(record) {
  loadDownloadHashes();
  const idx = downloadHashRecords.findIndex(r => r.id === record.id);
  if (idx >= 0) downloadHashRecords.splice(idx, 1);
  downloadHashRecords.push(record);
  if (downloadHashRecords.length > MAX_DOWNLOAD_HASH_RECORDS) {
    downloadHashRecords.splice(0, downloadHashRecords.length - MAX_DOWNLOAD_HASH_RECORDS);
  }
  persistDownloadHashes();
}

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
  loadDownloadHashes();
  downloadHashRecords.length = 0;
  try { fsSync.unlinkSync(downloadHashStorePath); } catch {}
  persistDownloadHashes();
  return true;
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
  bindRendererNotifier,
  bindWindowHost,
  queueDownloadHashing,
  listDownloadHashes,
  removeDownloadHashRecord,
  clearDownloadHashes,
  verifyDownloadHashById,
  hashLocalFileViaDialog,
};
