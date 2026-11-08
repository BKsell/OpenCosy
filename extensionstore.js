'use strict';

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

const MAX_TREE_DEPTH = 12;          // extensions/<id> 之下允许的最大目录深度
const MAX_ENTRY_COUNT = 4000;       // 一次安装允许复制的文件+目录总数
const MAX_TOTAL_BYTES = 256 * 1024 * 1024; // 一次安装允许的总字节（256MiB）
const MAX_ENTRY_NAME_BYTES = 255;   // 单个条目名的 UTF-8 字节上限
const MAX_ID_LENGTH = 128;

const COPY_ACCEPT_FILE = 'file';
const COPY_ACCEPT_DIR = 'dir';
const COPY_SKIP = 'skip';
const COPY_REJECT = 'reject';

function isAsciiAlnum(ch) {
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9');
}

// 名字段消毒：只保留 ASCII 字母数字，其余一律替成下划线（不用正则）。
function sanitizeNameToken(input) {
  const s = String(input == null ? '' : input);
  let out = '';
  for (let i = 0; i < s.length; i += 1) {
    out += isAsciiAlnum(s[i]) ? s[i] : '_';
  }
  return out;
}

// 版本段消毒：允许字母数字、点、下划线、连字符（语义化版本常见字符），其余替成下划线。
function sanitizeVersionToken(input) {
  const s = String(input == null ? '' : input);
  let out = '';
  for (let i = 0; i < s.length; i += 1) {
    const ch = s[i];
    out += (isAsciiAlnum(ch) || ch === '.' || ch === '_' || ch === '-') ? ch : '_';
  }
  return out;
}

// tokenCouldEscape 判断一个已消毒 token 是否含任何路径分隔/穿越风险。
function tokenHasSeparators(token) {
  if (typeof token !== 'string' || token.length === 0) return true;
  for (let i = 0; i < token.length; i += 1) {
    const ch = token[i];
    if (ch === '/' || ch === '\\' || ch === '\0') return true;
  }
  return false;
}

// containsAlnum 报告字符串是否至少含一个 ASCII 字母或数字（不用正则）。
function containsAlnum(s) {
  for (let i = 0; i < s.length; i += 1) {
    if (isAsciiAlnum(s[i])) return true;
  }
  return false;
}

// buildExtensionId 由 manifest 的 name/version 生成稳定且无路径风险的扩展 ID。
// 返回 null 表示消毒后没有任何有效字符（例如 name 全是符号），调用方应拒绝安装。
function buildExtensionId(name, version) {
  const namePart = sanitizeNameToken(name);
  const versionPart = sanitizeVersionToken(version);
  if (!containsAlnum(namePart) || !containsAlnum(versionPart)) return null;
  const id = `${namePart}_${versionPart}`;
  if (id.length > MAX_ID_LENGTH) return null;
  return id;
}

// utf8Length 返回字符串的 UTF-8 字节长度（Buffer 在 Electron 主进程与测试环境都可用，
// 且本函数不做任何 IO，保持纯逻辑）。
function utf8Length(s) {
  return Buffer.byteLength(String(s), 'utf8');
}

// hasControlChar 报告条目名是否含 NUL 或其他控制字符（终端/资源管理器难辨，拒绝）。
function hasControlChar(name) {
  for (let i = 0; i < name.length; i += 1) {
    if (name.charCodeAt(i) <= 0x1f || name.charCodeAt(i) === 0x7f) return true;
  }
  return false;
}

// hasReservedWindowsChar 报告是否含 Windows 保留字符。':' 尤其危险：NTFS 备用数据流
// （ADS）允许出现 "evil.exe:secret" 这类名，资源管理器只看到 evil.exe，是经典的文件
// 伪装/藏匿载体；'?'/'*' 是通配符，其余为 Windows 非法文件名字符。扩展在 Windows 上
// 加载，统一拒绝更安全。
function hasReservedWindowsChar(name) {
  for (let i = 0; i < name.length; i += 1) {
    const ch = name[i];
    if (ch === ':' || ch === '<' || ch === '>' || ch === '"' ||
        ch === '|' || ch === '?' || ch === '*') {
      return true;
    }
  }
  return false;
}

// isSafeEntryName 判定目录中的单个条目名能否参与复制/作为图标名。
// 拒绝：空、. / ..、含分隔符、Windows 保留字符（含 ADS 冒号）、控制字符、超长名、
// 绝对路径（盘符/UNC）。
function isSafeEntryName(name) {
  if (typeof name !== 'string' || name.length === 0) return false;
  if (name === '.' || name === '..') return false;
  if (name.includes('/') || name.includes('\\')) return false;
  if (hasControlChar(name) || hasReservedWindowsChar(name)) return false;
  if (utf8Length(name) > MAX_ENTRY_NAME_BYTES) return false;
  if (path.isAbsolute(name)) return false;
  return true;
}

// resolveWithinRoot 把若干段拼到 root 下，并保证归一化结果仍位于 root 之内。
// root 必须是绝对路径；逃逸（含 .. 折叠后跑出 root、Windows 盘符跳转）返回 null。
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
