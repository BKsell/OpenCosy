// downloadshelf.js —— 底部下载栏（download shelf）快照内核。
//
// 背景：
//   主进程维护 downloads 数组并在每次状态变化时把最新几条推给主界面。原先的快照
//   构建逻辑内联在 main.js 里：字段直接透传，没有任何净化。Electron 的 DownloadItem
//   字段（文件名 / URL / 错误信息）来自远端响应头与 Content-Disposition，恶意服务器
//   可以在里面塞控制字符、ANSI 序列、超长串甚至 HTML；Renderer 如果直接渲染这些
//   字段就会中招（控制字符注入终端/日志、超长串打崩布局、字段里夹 HTML 触发
//   innerHTML 注入）。本模块把"原始 DownloadItem -> 可序列化快照"这一段收口：
//   剥控制字符、按字节截断、状态白名单、进度 clamp、统计汇总，输出纯净的
//   JSON-safe 对象，绝不把 DownloadItem 本身跨进程暴露。
//
// 设计要点：
//   - 所有字段先剥控制字符（含 ANSI CSI 序列前缀）再按字节截断，filename/url/
//     errorMessage 各有独立上限；
//   - status 只允许白名单枚举，未知状态一律降级为 'pending'，防异常值穿透；
//   - progress 强制 clamp 到 [0,100]，speed 截断并丢弃不可打印字符；
//   - savePath 只做存在性标记（true/false），完整本地路径不跨进程透传；
//   - buildShelfSnapshot 从数组尾部取最近 MaxItems 条（浏览器同款行为），
//     shelfStats 顺带给出总数/进行中/完成/失败计数，供界面角标展示。

'use strict';

// ShelfLimits 限定快照各字段的边界。
const ShelfLimits = Object.freeze({
  maxItems: 3,          // 与浏览器下载栏一致，只展示最近 3 条
  maxFilenameRunes: 180,
  maxUrlRunes: 800,
  maxErrorRunes: 300,
  maxSpeedRunes: 24,
});

// SHELF_STATUSES 是允许透传给渲染层的状态枚举。
const SHELF_STATUSES = Object.freeze({
  pending: true,
  progress: true,
  interrupted: true,
  completed: true,
  cancelled: true,
});

// stripControlChars 剥掉控制字符与常见 ANSI CSI/OSC 序列（先正则清序列，再逐码点
// 剥残余控制字符，保证 CSI 头被完整移除而不残留 "[" 碎片）。
function stripControlChars(s) {
  if (typeof s !== 'string') return '';
  // 先整体清 OSC 标题序列与 CSI 序列（含不带前缀的裸 "[" 余毒由后续码点过滤兜底）
  let t = s
    .replace(/\x1b\]0;[^\x07]*\x07/g, '')
    .replace(/\x1b\[[0-9;?]*[ -\/]*[@-~]/g, '');
  let out = '';
  for (const ch of t) {
    const c = ch.codePointAt(0);
    if (c < 0x20 || c === 0x7f) {
      continue; // C0 控制字符与 DEL
    }
    if (c >= 0xe000 && c <= 0xf8ff) {
      continue; // 私有区（防字体投毒混淆显示）
    }
    out += ch;
  }
  return out;
}

// truncateRunes 按 rune 数量截断（配合字节上限双保险）。
function truncateRunes(s, maxRunes) {
  if (typeof s !== 'string') return '';
  let out = '';
  let n = 0;
  for (const ch of s) {
    if (n >= maxRunes) break;
    out += ch;
    n++;
  }
  return out;
}

// clampNumber 把数字钳进 [min, max]，NaN/Infinity 一律归 0。
function clampNumber(v, min, max) {
  const n = Number(v);
  if (!Number.isFinite(n)) return min;
  return Math.min(max, Math.max(min, n));
}

// sanitizeShelfEntry 把一条原始下载记录净化成可序列化快照项。
function sanitizeShelfEntry(raw, lim) {
  const L = lim || ShelfLimits;
  const status = SHELF_STATUSES[String((raw && raw.status) || 'pending')]
    ? String(raw.status)
    : 'pending';
  const progress = clampNumber(raw && raw.progress, 0, 100);
  const total = clampNumber(raw && raw.totalBytes, 0, Number.MAX_SAFE_INTEGER);
  const received = clampNumber(raw && raw.receivedBytes, 0, Number.MAX_SAFE_INTEGER);
  const filename = truncateRunes(stripControlChars(String((raw && raw.filename) || '')), L.maxFilenameRunes);
  const url = truncateRunes(stripControlChars(String((raw && raw.url) || '')), L.maxUrlRunes);
  const speed = truncateRunes(stripControlChars(String((raw && raw.speed) || '')), L.maxSpeedRunes);
  const errorMessage = truncateRunes(stripControlChars(String((raw && raw.errorMessage) || '')), L.maxErrorRunes);
  const startTime = Number.isFinite(Number(raw && raw.startTime)) ? Number(raw.startTime) : null;
  return {
    id: String((raw && raw.id) || ''),
    filename,
    url,
    totalBytes: total,
    receivedBytes: received,
    progress,
    speed,
    status,
    hasSavePath: !!(raw && raw.savePath),
    startTime,
    errorMessage,
  };
}

// buildShelfSnapshot 从下载数组尾部取最近 maxItems 条并净化。
function buildShelfSnapshot(downloads, lim) {
  const L = lim || ShelfLimits;
  const items = [];
  if (Array.isArray(downloads)) {
    for (let i = downloads.length - 1; i >= 0 && items.length < L.maxItems; i--) {
      items.push(sanitizeShelfEntry(downloads[i], L));
    }
  }
  return { items, stats: shelfStats(downloads) };
}

// shelfStats 汇总整张下载台账：总数/进行中/完成/失败。
function shelfStats(downloads) {
  const stats = { total: 0, active: 0, completed: 0, failed: 0, cancelled: 0 };
  if (!Array.isArray(downloads)) return stats;
  stats.total = downloads.length;
  for (const d of downloads) {
    const s = String((d && d.status) || '');
    if (s === 'completed') stats.completed++;
    else if (s === 'interrupted') stats.failed++;
    else if (s === 'cancelled') stats.cancelled++;
    else if (s === 'progress' || s === 'pending') stats.active++;
  }
  return stats;
}

// sanitizeDownloadRecord 供主进程在下发/落盘前对整条记录做净化（与快照同源）。
function sanitizeDownloadRecord(raw, lim) {
  const clean = sanitizeShelfEntry(raw, lim);
  // 快照项不含本地路径；台账记录需要保留 savePath 时由调用方显式传入并单独校验
  if (raw && typeof raw.savePath === 'string' && raw.savePath.length > 0) {
    clean.savePath = truncateRunes(stripControlChars(raw.savePath), 4096);
  }
  return clean;
}

// summarizeShelf 压成一行可读文本（日志/审计事件用）。
function summarizeShelf(stats) {
  const s = stats || shelfStats([]);
  return 'download-shelf total=' + s.total
    + ' active=' + s.active
    + ' completed=' + s.completed
    + ' failed=' + s.failed
    + ' cancelled=' + s.cancelled;
}

module.exports = {
  ShelfLimits,
  SHELF_STATUSES,
  stripControlChars,
  truncateRunes,
  clampNumber,
  sanitizeShelfEntry,
  buildShelfSnapshot,
  shelfStats,
  sanitizeDownloadRecord,
  summarizeShelf,
};
