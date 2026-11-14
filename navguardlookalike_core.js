'use strict';

// 仅在 Node 环境取 domainToUnicode；浏览器/缺省环境下降级为“不解码”。
let domainToUnicode = null;
try {
  // eslint-disable-next-line global-require
  const nodeUrl = require('url');
  if (typeof nodeUrl.domainToUnicode === 'function') {
    domainToUnicode = nodeUrl.domainToUnicode;
  }
} catch { domainToUnicode = null; }
// 西里尔字母 → 视觉等价拉丁字母（只收录高置信的同形字，用码位显式列出）。
const CYRILLIC_LOOKALIKES = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y',
  'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
  'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
  'ь': 'b', 'ѕ': 's', 'і': 'i', 'ј': 'j',
  'ԁ': 'd', 'ԓ': 'l', 'ԛ': 'q', 'ԝ': 'w',
};

// 希腊字母 → 视觉等价拉丁字母（码位显式列出，避免肉眼重复）。
const GREEK_LOOKALIKES = {
  'ο': 'o', 'ε': 'e', 'α': 'a', 'ρ': 'p', 'ν': 'v', 'ι': 'i',
  'κ': 'k', 'μ': 'm', 'τ': 't', 'χ': 'x', 'υ': 'y',
  'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I',
  'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T',
  'Υ': 'Y', 'Χ': 'X',
};

// 数字 / 符号 → 易混字母（用于无分隔连写标签的弱信号）。
const DIGIT_LOOKALIKES = {
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't',
};

function isAsciiLetter(ch) {
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
}
function isAsciiDigit(ch) {
  return ch >= '0' && ch <= '9';
}

// scriptOfCodePoint 粗分类单个字符所属脚本族。
function scriptOfCodePoint(cp) {
  if ((cp >= 0x0041 && cp <= 0x005A) || (cp >= 0x0061 && cp <= 0x007A)) return 'Latin';
  if (cp >= 0x0030 && cp <= 0x0039) return 'Digit';
  if (cp === 0x002D || cp === 0x002E) return 'Common'; // - .
  if (cp >= 0x0400 && cp <= 0x04FF) return 'Cyrillic';
  if (cp >= 0x0500 && cp <= 0x052F) return 'Cyrillic'; // 西里尔扩展
  if (cp >= 0x1C80 && cp <= 0x1C8F) return 'Cyrillic';
  if (cp >= 0x0370 && cp <= 0x03FF) return 'Greek';
  if (cp >= 0x1F00 && cp <= 0x1FFF) return 'Greek';
  return 'Other';
}

// countScripts 统计一个标签里出现的“有意义”脚本族（拉丁/西里尔/希腊）。
function countScripts(label) {
  const scripts = new Set();
  for (const ch of label) {
    const s = scriptOfCodePoint(ch.codePointAt(0));
    if (s === 'Latin' || s === 'Cyrillic' || s === 'Greek') scripts.add(s);
  }
  return scripts;
}

// mapToLatinLookalike 尝试把整标签映射成纯拉丁串。
// 返回 { mapped, changed }：只有当每个非 ASCII 字母都能映射、且结果仍像
// 域名标签（[A-Za-z0-9-]）时才算成功的同形候选。
function mapToLatinLookalike(label) {
  let mapped = '';
  let changed = false;
  for (const ch of label) {
    if (isAsciiLetter(ch) || isAsciiDigit(ch) || ch === '-') {
      mapped += ch;
    } else if (Object.prototype.hasOwnProperty.call(CYRILLIC_LOOKALIKES, ch)) {
      mapped += CYRILLIC_LOOKALIKES[ch];
      changed = true;
    } else if (Object.prototype.hasOwnProperty.call(GREEK_LOOKALIKES, ch)) {
      mapped += GREEK_LOOKALIKES[ch];
      changed = true;
    } else {
      return { mapped: '', changed: false, ok: false };
    }
  }
  return { mapped, changed, ok: changed && /^[A-Za-z0-9-]+$/.test(mapped) };
}

// decodePunyLabel 把单个 xn-- 标签解码成 Unicode；失败返回空串。
function decodePunyLabel(label) {
  if (!label || label.toLowerCase().indexOf('xn--') !== 0) return '';
  if (domainToUnicode) {
    try {
      const u = domainToUnicode(label);
      return u && u !== label ? u : '';
    } catch { return ''; }
  }
  return '';
}

// splitLabels 切主机名为小写标签数组（去尾点）。

module.exports = {
  CYRILLIC_LOOKALIKES,
  GREEK_LOOKALIKES,
  DIGIT_LOOKALIKES,
  isAsciiLetter,
  isAsciiDigit,
  scriptOfCodePoint,
  countScripts,
  mapToLatinLookalike,
  decodePunyLabel,
};
