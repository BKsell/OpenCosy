'use strict';
const { ARCHIVE_EXTS, MACRO_OFFICE_EXTS, LEGACY_OFFICE_MACRO_EXTS, SELF_EXTRACTING_EXTS, KIND_ARCHIVE, KIND_MACRO_OFFICE, KIND_LEGACY_OFFICE, KIND_SELF_EXTRACTING, KIND_NONE, RISK_ALLOW, RISK_WARN, RISK_CONFIRM, extLower, classifyContainer, describeContainerRisk, isContainerExt } = require('./containerkind');

// container.js —— 下载“容器类文件”的风险判定内核。
//
// Mark-of-the-Web 只标记下载到的那个文件本身，不会随解压/另存自动传播到容器
// 内部：一个带 MOTW 的 invoice.zip 解出来的 invoice.exe 是“本地文件”，SmartScreen
// 不再提示；带宏的 .docm/.xlsm 同理（.docx 改后缀、宏执行）。磁盘镜像、自解压
// 安装包也是常见投递载体。因此对“来自互联网的容器”不能只按普通下载处理，打开 /
// 解压前要单独提示，并给出“解压后需逐文件重新隔离”的处置建议。
//
// 本内核纯判定、不碰 fs；与 quarantine.js 配合（后者负责扩展名可执行判定与
// ZoneId）。

// 归档类：内部可藏任意可执行文件，MOTW 不继承。
const MAX_EXTRACTION_ENTRIES = 100000;

const EXTRACT_RISK_EXTS = new Set([
  '.exe', '.scr', '.com', '.bat', '.cmd', '.ps1', '.psm1', '.vbs', '.vbe',
  '.js', '.jse', '.wsf', '.wsh', '.msi', '.msp', '.mst', '.jar', '.cpl',
  '.msc', '.reg', '.lnk', '.hta', '.dll', '.ocx', '.sys', '.drv',
  '.docm', '.dotm', '.xlsm', '.xltm', '.xlam', '.pptm', '.ppam', '.ppsm',
  '.doc', '.xls', '.ppt', '.zip', '.rar', '.7z', '.iso', '.img', '.cab',
]);

function planExtractionMotw(entries) {
  const list = Array.isArray(entries) ? entries : [];
  const stamped = [];
  let truncated = false;
  let scanned = 0;
  for (const raw of list) {
    if (scanned >= MAX_EXTRACTION_ENTRIES) { truncated = true; break; }
    scanned += 1;
    if (typeof raw !== 'string' || !raw) continue;
    // 规整路径分隔符并取末段（归档内可能是目录形式）。
    const norm = raw.replace(/\\/g, '/').replace(/\/+$/, '');
    const base = norm.slice(norm.lastIndexOf('/') + 1);
    const ext = extLower(base);
    if (ext && EXTRACT_RISK_EXTS.has(ext)) {
      stamped.push(norm);
    }
  }
  return {
    stamped,
    stampedCount: stamped.length,
    scanned,
    truncated,
    limit: MAX_EXTRACTION_ENTRIES,
  };
}

// openContainerDecision 综合“容器分类 + 是否来自互联网”给出打开前决策。
// 入参 { filename, fromWeb }。
//   来自互联网：confirm 类 → 'confirm'，archive 类 → 'confirm'（打开/解压即提示）；
//   本地文件：宏/自解压仍轻提示 'warn'，普通归档放行。
function openContainerDecision(input) {
  const m = input || {};
  const c = classifyContainer(m.filename);
  if (c.kind === KIND_NONE) return RISK_ALLOW;
  if (m.fromWeb === true) return RISK_CONFIRM;
  if (c.risk === RISK_CONFIRM) return RISK_WARN;
  return RISK_ALLOW;
}

module.exports = {
  ARCHIVE_EXTS,
  MACRO_OFFICE_EXTS,
  LEGACY_OFFICE_MACRO_EXTS,
  SELF_EXTRACTING_EXTS,
  EXTRACT_RISK_EXTS,
  KIND_ARCHIVE,
  KIND_MACRO_OFFICE,
  KIND_LEGACY_OFFICE,
  KIND_SELF_EXTRACTING,
  KIND_NONE,
  RISK_ALLOW,
  RISK_WARN,
  RISK_CONFIRM,
  MAX_EXTRACTION_ENTRIES,
  extLower,
  classifyContainer,
  describeContainerRisk,
  isContainerExt,
  planExtractionMotw,
  openContainerDecision,
};
