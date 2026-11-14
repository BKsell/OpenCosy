"use strict";

const path = require('path');
const { hasControlCharsV2: hasControlChar } = require('./modutil');

const MAX_TREE_DEPTH = 12;          // extensions/<id> 之下允许的最大目录深度

const MAX_ENTRY_COUNT = 4000;       // 一次安装允许复制的文件+目录总数

const MAX_TOTAL_BYTES = 256 * 1024 * 1024; // 一次安装允许的总字节（256MiB）

const MAX_ENTRY_NAME_BYTES = 255;   // 单个条目名的 UTF-8 字节上限

const MAX_ID_LENGTH = 128;

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

module.exports = { MAX_TREE_DEPTH, MAX_ENTRY_COUNT, MAX_TOTAL_BYTES, MAX_ENTRY_NAME_BYTES, MAX_ID_LENGTH, isAsciiAlnum, sanitizeNameToken, sanitizeVersionToken, tokenHasSeparators, containsAlnum, buildExtensionId, utf8Length, hasReservedWindowsChar, isSafeEntryName };
