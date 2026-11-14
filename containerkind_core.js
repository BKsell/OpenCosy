"use strict";

const ARCHIVE_EXTS = new Set([
  '.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.tbz2',
  '.tbz', '.tb2', '.lz', '.lzma', '.zst', '.cab', '.iso', '.img', '.vhd',
  '.vhdx', '.wim', '.arj', '.lzh', '.lha', '.ace', '.bz', '.jar', '.war',
  '.nupkg', '.apk', '.xapk', '.dmg',
]);

// Office 宏 / 可活动内容容器（可携带 VBA / 宏 4.0 / DDE / OLE 嵌入）。
const MACRO_OFFICE_EXTS = new Set([
  '.docm', '.dotm', '.xlsm', '.xltm', '.xlam', '.pptm', '.potm', '.ppam',
  '.ppsm',
]);

// 老式 Office 二进制格式本身允许宏（doc/xls/ppt/pps 等默认即可含宏）。
const LEGACY_OFFICE_MACRO_EXTS = new Set([
  '.doc', '.dot', '.xls', '.xlt', '.xla', '.ppt', '.pot', '.pps',
]);

// 自解压 / 安装类容器（本质是可执行，但常被当“压缩包”信任）。
const SELF_EXTRACTING_EXTS = new Set([
  '.exe', '.msi', '.msp', '.sfx',
]);

const KIND_ARCHIVE = 'archive';
const KIND_MACRO_OFFICE = 'macro-office';
const KIND_LEGACY_OFFICE = 'legacy-office';
const KIND_SELF_EXTRACTING = 'self-extracting';
const KIND_NONE = 'none';

const RISK_ALLOW = 'allow';
const RISK_WARN = 'warn';
const RISK_CONFIRM = 'confirm';

// extLower 取小写扩展名（含点）。
function extLower(name) {
  const s = String(name || '');
  const slash = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'));
  const base = slash >= 0 ? s.slice(slash + 1) : s;
  const dot = base.lastIndexOf('.');
  if (dot <= 0) return '';
  return base.slice(dot).toLowerCase();
}

// classifyContainer 返回容器分类结果：
// { kind, risk, reasons:[] }。
//   - 宏 / 老式 Office、自解压 → confirm（最容易直接执行恶意内容）；
//   - 普通归档 → warn（本身不执行，提示解压后隔离）。
function classifyContainer(name) {
  const ext = extLower(name);
  const reasons = [];
  if (!ext) return { kind: KIND_NONE, risk: RISK_ALLOW, reasons, ext: '' };

  if (MACRO_OFFICE_EXTS.has(ext)) {
    reasons.push('macro-enabled-office-document');
    return { kind: KIND_MACRO_OFFICE, risk: RISK_CONFIRM, reasons, ext };
  }
  if (LEGACY_OFFICE_MACRO_EXTS.has(ext)) {
    reasons.push('legacy-office-may-contain-macro');
    return { kind: KIND_LEGACY_OFFICE, risk: RISK_CONFIRM, reasons, ext };
  }
  if (SELF_EXTRACTING_EXTS.has(ext)) {
    reasons.push('self-extracting-or-installer');
    return { kind: KIND_SELF_EXTRACTING, risk: RISK_CONFIRM, reasons, ext };
  }
  if (ARCHIVE_EXTS.has(ext)) {
    reasons.push('archive-mark-of-the-web-not-inherited');
    // 磁盘镜像里的文件同样不带 MOTW，且可被自动挂载执行。
    if (ext === '.iso' || ext === '.img' || ext === '.vhd' || ext === '.vhdx' || ext === '.dmg') {
      reasons.push('disk-image-auto-mount');
    }
    return { kind: KIND_ARCHIVE, risk: RISK_WARN, reasons, ext };
  }
  return { kind: KIND_NONE, risk: RISK_ALLOW, reasons, ext };
}

// describeContainerRisk 给出面向用户的一句话处置说明。
function describeContainerRisk(classification) {
  const c = classification || {};
  switch (c.kind) {
    case KIND_MACRO_OFFICE:
    case KIND_LEGACY_OFFICE:
      return '该 Office 文档可能包含宏或活动内容，打开后如提示“启用宏/启用内容”，请勿启用。';
    case KIND_SELF_EXTRACTING:
      return '该文件会自行解压或安装程序，等同运行可执行文件。';
    case KIND_ARCHIVE:
      return '压缩包内的文件不会继承“来自互联网”的安全标记，解压后请先确认内部文件再打开。';
    default:
      return '';
  }
}

// isContainerExt 便于外部快速判断。
function isContainerExt(name) {
  return classifyContainer(name).kind !== KIND_NONE;
}

// planExtractionMotw 是给“解压工具”用的纯规划器：给定解出的相对路径清单，
// 返回其中在隔离语义下需要被当作“来自互联网”处理的条目。规则：
//   - 可执行 / 脚本 / 宏文档 / 嵌套容器都需要重新打标；
//   - 普通静态文件（txt/png 等）不需要。
// entries 为字符串数组（相对路径，使用 / 或 \\）；有上限，防止清单炸弹。

module.exports = { ARCHIVE_EXTS, MACRO_OFFICE_EXTS, LEGACY_OFFICE_MACRO_EXTS, SELF_EXTRACTING_EXTS, KIND_ARCHIVE, KIND_MACRO_OFFICE, KIND_LEGACY_OFFICE, KIND_SELF_EXTRACTING, KIND_NONE, RISK_ALLOW, RISK_WARN, RISK_CONFIRM, extLower, classifyContainer, describeContainerRisk, isContainerExt };
