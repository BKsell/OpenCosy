'use strict';

// quarantine.js —— 下载文件的“来源隔离”内核（Electron/Windows 的 Mark-of-the-Web）。
//
// Windows 对“来自互联网”的文件会附带 NTFS 备用数据流（ADS）
// “文件名:Zone.Identifier”，内容形如 [ZoneTransfer] ZoneId=3。Shell、Office、
// 杀软据此弹“来自 Internet”的保护提示（SmartScreen / 受保护视图）。Chromium
// 下载时本应自动写入，但经 setSavePath 自定义落盘、跨盘移动、从压缩包解出等
// 情况可能丢失 MOTW；非 Windows 平台也没有 ADS。
//
// 这里在下载完成后显式补写 Zone.Identifier（best-effort，失败不影响下载），
// 并提供“打开来自互联网的可执行文件前二次确认”的纯判定，供主进程 open-file
// IPC 复用。内核不直接 require('fs')，文件操作通过注入的 fsImpl 完成，便于单测。

var ZONE_LOCAL_MACHINE = 0;
var ZONE_INTRANET = 1;
var ZONE_TRUSTED = 2;
var ZONE_INTERNET = 3;
var ZONE_RESTRICTED = 4;

// 控制字符区间（不含 \t），用于剥掉 ADS 字段里可能伪造的不可见字符。
var CONTROL_RE = /[\x00-\x08\x0b\x0c\x0e-\x1f]/g;

// 打开前必须二次确认的可执行 / 脚本 / 安装包扩展名（小写、含点）。
var OPEN_RISK_EXTS = new Set([
  '.exe', '.scr', '.com', '.bat', '.cmd', '.ps1', '.psm1', '.vbs', '.vbe',
  '.js', '.jse', '.wsf', '.wsh', '.msi', '.msp', '.mst', '.jar', '.cpl',
  '.msc', '.reg', '.lnk', '.hta', '.dll',
]);

// isPrivateHostname 判定主机是否为私网 / 回环（与主进程口径一致，内核自带一份
// 轻量实现，避免与 Electron 主文件产生循环依赖）。
function isPrivateHostname(hostname) {
  var h = String(hostname || '').toLowerCase().replace(/\.$/, '');
  if (!h) return false;
  if (h === 'localhost' || h === '::1' || h === '[::1]') return true;
  var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (m) {
    var a = Number(m[1]);
    var b = Number(m[2]);
    if (a === 10 || a === 127) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 169 && b === 254) return true; // 链路本地
    if (a === 0) return true;
    return false;
  }
  if (h.indexOf('.') === -1) return true; // 裸主机名视为内网
  if (endsWithDotSuffix(h, '.local')) return true;
  if (endsWithDotSuffix(h, '.internal')) return true;
  if (endsWithDotSuffix(h, '.lan')) return true;
  return false;
}

// endsWithDotSuffix 判断 h 是否以指定后缀结尾，且 lastIndexOf 必须真实命中
// （避免“字符串比后缀还短”时 -1 与负偏移相等的误判）。
function endsWithDotSuffix(h, suffix) {
  var idx = h.lastIndexOf(suffix);
  return idx !== -1 && idx === h.length - suffix.length;
}

// zoneForUrl 依据下载 URL 选择 MOTW ZoneId；无法解析 / 不明确协议保守归 Internet。
function zoneForUrl(rawUrl) {
  var u;
  try {
    u = new URL(rawUrl);
  } catch (e) {
    return ZONE_INTERNET;
  }
  if (u.protocol === 'file:') return ZONE_LOCAL_MACHINE;
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return ZONE_INTERNET;
  if (isPrivateHostname(u.hostname)) return ZONE_INTRANET;
  return ZONE_INTERNET;
}

// extOf 取小写扩展名（含点）；无扩展名 / 隐藏文件返回空串。
function extOf(filePath) {
  var name = String(filePath || '');
  var slash = Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\'));
  var base = slash >= 0 ? name.slice(slash + 1) : name;
  var dot = base.lastIndexOf('.');
  if (dot <= 0) return '';
  return base.slice(dot).toLowerCase();
}

function isOpenRiskExt(filePath) {
  return OPEN_RISK_EXTS.has(extOf(filePath));
}

// sanitizeZoneField 去掉换行 / 控制字符，防止伪造 URL 往 ADS ini 文本里注入
// 额外键值（换行会变成新字段）；长度封顶，避免异常超长值。
function sanitizeZoneField(value) {
  return String(value == null ? '' : value)
    .replace(/[\r\n]+/g, ' ')
    .replace(CONTROL_RE, '')
    .slice(0, 2048)
    .trim();
}

// formatZoneIdentifier 生成标准 Zone.Identifier ADS 文本（CRLF，结尾留空行）。
function formatZoneIdentifier(meta) {
  var m = meta || {};
  var zone = Number.isInteger(m.zoneId) ? m.zoneId : zoneForUrl(m.hostUrl);
  var lines = ['[ZoneTransfer]', 'ZoneId=' + zone];
  var referrer = sanitizeZoneField(m.referrerUrl);
  var host = sanitizeZoneField(m.hostUrl);
  if (referrer) lines.push('ReferrerUrl=' + referrer);
  if (host) lines.push('HostUrl=' + host);
  if (m.lastWriteTime) lines.push('LastWrittenTime=' + sanitizeZoneField(m.lastWriteTime));
  return lines.join('\r\n') + '\r\n';
}

// adsStreamPath 返回 Windows NTFS 备用数据流路径：C:\dir\f.exe:Zone.Identifier
function adsStreamPath(filePath) {
  return String(filePath || '') + ':Zone.Identifier';
}

// isWebDownload 判断元数据是否来自“互联网”（才需要 MOTW / 二次确认）。
function isWebDownload(input) {
  if (input == null) return false;
  if (typeof input === 'number') return input === ZONE_INTERNET || input === ZONE_RESTRICTED;
  var zone = zoneForUrl(input);
  return zone === ZONE_INTERNET || zone === ZONE_RESTRICTED;
}

// applyMarkOfTheWeb 尝试给已落地文件写 MOTW。文件操作经 fsImpl 注入：
//   fsImpl.platform             显式平台（'win32' 等），默认 process.platform
//   fsImpl.appendFileSync(p,c)  追加写入（必需）
// 返回 { wrote, platform, stream, reason }；任何失败都不抛出（best-effort）。
function applyMarkOfTheWeb(fsImpl, filePath, meta) {
  var platform = (fsImpl && fsImpl.platform) ||
    (typeof process !== 'undefined' && process.platform) || 'unknown';

  if (!filePath || typeof filePath !== 'string') {
    return { wrote: false, platform: platform, stream: '', reason: 'invalid-path' };
  }
  if (!fsImpl || typeof fsImpl.appendFileSync !== 'function') {
    return { wrote: false, platform: platform, stream: '', reason: 'no-fs' };
  }
  if (platform !== 'win32') {
    return { wrote: false, platform: platform, stream: '', reason: 'unsupported-platform' };
  }
  var hostUrl = meta && meta.hostUrl;
  var zoneId = meta && meta.zoneId;
  if (!isWebDownload(zoneId != null ? zoneId : hostUrl)) {
    return { wrote: false, platform: platform, stream: '', reason: 'not-internet' };
  }

  var content = formatZoneIdentifier(meta);
  var stream = adsStreamPath(filePath);
  try {
    fsImpl.appendFileSync(stream, content);
    return { wrote: true, platform: platform, stream: stream, reason: 'ok' };
  } catch (err) {
    // 目标盘非 NTFS（FAT/exFAT）或权限不足时 ADS 写入失败，属正常情况。
    return {
      wrote: false,
      platform: platform,
      stream: stream,
      reason: 'write-failed',
      error: String(err && err.message || err),
    };
  }
}

// openDecision 决定“打开一个已下载文件”前是否要二次确认：
//   - 可执行 / 脚本 / 安装包扩展名，且来自互联网（或来源未知）→ 'confirm'
//   - 其余 → 'allow'
// 入参 { filePath, hostUrl, zoneId }。
function openDecision(input) {
  var m = input || {};
  if (!m.filePath) return 'allow';
  if (!isOpenRiskExt(m.filePath)) return 'allow';
  if (m.hostUrl == null && m.zoneId == null) return 'confirm';
  var fromWeb = m.zoneId != null
    ? (m.zoneId === ZONE_INTERNET || m.zoneId === ZONE_RESTRICTED)
    : isWebDownload(m.hostUrl);
  return fromWeb ? 'confirm' : 'allow';
}

module.exports = {
  ZONE_LOCAL_MACHINE: ZONE_LOCAL_MACHINE,
  ZONE_INTRANET: ZONE_INTRANET,
  ZONE_TRUSTED: ZONE_TRUSTED,
  ZONE_INTERNET: ZONE_INTERNET,
  ZONE_RESTRICTED: ZONE_RESTRICTED,
  OPEN_RISK_EXTS: OPEN_RISK_EXTS,
  isPrivateHostname: isPrivateHostname,
  zoneForUrl: zoneForUrl,
  extOf: extOf,
  isOpenRiskExt: isOpenRiskExt,
  sanitizeZoneField: sanitizeZoneField,
  formatZoneIdentifier: formatZoneIdentifier,
  adsStreamPath: adsStreamPath,
  applyMarkOfTheWeb: applyMarkOfTheWeb,
  isWebDownload: isWebDownload,
  openDecision: openDecision,
};
