'use strict';
const { MAX_TREE_DEPTH, MAX_ENTRY_COUNT, MAX_TOTAL_BYTES, MAX_ENTRY_NAME_BYTES, MAX_ID_LENGTH, sanitizeNameToken, sanitizeVersionToken, tokenHasSeparators, buildExtensionId, utf8Length, isSafeEntryName } = require('./extstorenames_core');
const { hasControlCharsV2: hasControlChar } = require('./modutil_core');

// extensionstore.js — 扩展存储安全内核（纯函数，不接触磁盘）。
//
// 背景：扩展以“渲染层给一个本地目录 → 递归复制进 userData/extensions → loadExtension
// 持久化加载”的方式安装，权限高且跨重启。历史实现有两处隐患：
//   1. 扩展名/版本用内联 replace 消毒，规则散落在 IPC 里；
//   2. 递归复制用了不存在的 stat.IsSymbolicLink()（Node 真实方法是
//      isSymbolicLink，小写 i），调用必抛 TypeError，复制永远失败，符号链接保护
//      也从未真正执行；且复制没有深度/数量/体积上限，一个恶意目录可耗尽磁盘。
// 本模块把“ID 怎么来、路径必须落在哪、条目能不能复制、预算是否耗尽”全部收成
// 可单测的纯逻辑，main 进程只负责喂真实 lstat 结果。

const path = require('path');


const COPY_ACCEPT_FILE = 'file';
const COPY_ACCEPT_DIR = 'dir';
const COPY_SKIP = 'skip';
const COPY_REJECT = 'reject';

function resolveWithinRoot(root) {
  const segments = Array.prototype.slice.call(arguments, 1);
  if (typeof root !== 'string' || !path.isAbsolute(root)) return null;
  const target = path.resolve.apply(path, [root].concat(segments));
  const rootNorm = path.resolve(root);
  if (target === rootNorm) return target;
  const withSep = rootNorm.endsWith(path.sep) ? rootNorm : rootNorm + path.sep;
  return target.startsWith(withSep) ? target : null;
}

// resolveExtensionDir 解析某个扩展 ID 对应的安装目录，只接受单段、无分隔符的 ID，
// 且结果必须在 extensionsRoot 之内。用于复制目标、加载、删除（递归 rm）前的收口，
// 防止配置文件被篡改后用 id="../xxx" 把删除范围带出扩展目录。
function resolveExtensionDir(extensionsRoot, id) {
  if (typeof id !== 'string' || tokenHasSeparators(id)) return null;
  if (id === '.' || id === '..' || id.length > MAX_ID_LENGTH) return null;
  return resolveWithinRoot(extensionsRoot, id);
}

// createCopyBudget 创建一次安装的复制预算计数器（纯内存）。
function createCopyBudget(limits) {
  const lim = limits || {};
  const maxDepth = typeof lim.maxDepth === 'number' ? lim.maxDepth : MAX_TREE_DEPTH;
  const maxEntries = typeof lim.maxEntries === 'number' ? lim.maxEntries : MAX_ENTRY_COUNT;
  const maxBytes = typeof lim.maxBytes === 'number' ? lim.maxBytes : MAX_TOTAL_BYTES;
  return {
    depth: 0,
    entries: 0,
    bytes: 0,
    maxDepth,
    maxEntries,
    maxBytes,
    noteEntry() { this.entries += 1; return this.entries <= this.maxEntries; },
    addBytes(size) {
      const n = Number(size) || 0;
      if (n < 0 || this.bytes + n > this.maxBytes) return false;
      this.bytes += n;
      return true;
    },
  };
}

// classifyCopyEntry 是复制循环的纯判定。entry 需带真实 lstat 得到的信息：
//   { name, symlink:boolean, directory:boolean, size:number }
// depth 是该条目相对 extensions/<id> 的深度（id 目录本身算 0）。
// 返回：
//   { action:'file' }  普通文件，调用方 copyFile；
//   { action:'dir' }   普通目录，调用方递归；
//   { action:'skip', reason }  符号链接或非法名，静默跳过（不中断安装）；
//   { action:'reject', reason } 超出预算/深度/体积，必须整体中止安装。
function classifyCopyEntry(entry, depth, budget) {
  const e = entry || {};
  if (e.symlink) return { action: COPY_SKIP, reason: 'symlink' };
  if (!isSafeEntryName(e.name)) return { action: COPY_SKIP, reason: 'unsafe-name' };
  if (depth > budget.maxDepth) return { action: COPY_REJECT, reason: 'depth-exceeded' };
  if (!budget.noteEntry()) return { action: COPY_REJECT, reason: 'entry-count-exceeded' };
  if (e.directory) return { action: COPY_ACCEPT_DIR };
  if (!budget.addBytes(e.size)) return { action: COPY_REJECT, reason: 'total-bytes-exceeded' };
  return { action: COPY_ACCEPT_FILE };
}

module.exports = {
  MAX_TREE_DEPTH,
  MAX_ENTRY_COUNT,
  MAX_TOTAL_BYTES,
  MAX_ENTRY_NAME_BYTES,
  MAX_ID_LENGTH,
  COPY_ACCEPT_FILE,
  COPY_ACCEPT_DIR,
  COPY_SKIP,
  COPY_REJECT,
  sanitizeNameToken,
  sanitizeVersionToken,
  buildExtensionId,
  isSafeEntryName,
  hasControlChar,
  utf8Length,
  resolveWithinRoot,
  resolveExtensionDir,
  createCopyBudget,
  classifyCopyEntry,
};
