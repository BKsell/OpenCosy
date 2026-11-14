'use strict';

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

module.exports = { stripControlChars, truncateRunes, clampNumber };
