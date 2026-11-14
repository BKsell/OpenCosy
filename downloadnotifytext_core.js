'use strict';

// stripControlChars 剥掉不可打印字符（含换行、ESC 及其引导的 CSI 序列），防
// 日志/通知注入；保留中文等多字节 UTF-8（逐字节判断，0x20 以下与 0x7f 丢弃）。
// ESC 序列整段剥（不只是 ESC 本身），避免残留 “[31m” 这类可见垃圾。
function stripControlChars(s) {
  const src = String(s == null ? '' : s);
  const out = [];
  for (let i = 0; i < src.length; i++) {
    const c = src.charCodeAt(i);
    if (c === 0x1b) {
      // ESC [ 引导的 CSI：跳到终字节（0x40-0x7E）整段丢弃；孤立 ESC 也丢弃。
      if (src.charCodeAt(i + 1) === 0x5b) {
        i += 2;
        while (i < src.length && !(src.charCodeAt(i) >= 0x40 && src.charCodeAt(i) <= 0x7e)) i++;
      }
      continue;
    }
    if (c < 0x20 || c === 0x7f) continue;
    out.push(src[i]);
  }
  return out.join('');
}

// truncateUtf8 按字节上限截断字符串，避免在 UTF-8 多字节字符中间切断产生乱码。
function truncateUtf8(s, maxBytes) {
  let limit = maxBytes;
  if (Buffer.byteLength(s, 'utf8') <= limit) return s;
  let out = '';
  for (const ch of s) {
    const need = Buffer.byteLength(ch, 'utf8');
    if (limit - need < 0) break;
    out += ch;
    limit -= need;
  }
  return out;
}

// formatSize 人类可读大小（B/KB/MB/GB），与 renderer 的下载栏展示保持一致。
function formatSize(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n < 0) return '';
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n;
  let i = -1;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i < 0 ? 0 : 1)} ${units[i]}`;
}

module.exports = { stripControlChars, truncateUtf8, formatSize };
