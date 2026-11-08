'use strict';

// menuguard.js —— context-menu 事件 params 的统一净化内核。
//
// 威胁模型：
//   'context-menu' 的 params 完全来自被浏览网页：linkURL / srcURL / frameURL /
//   pageURL / selectionText / misspelledWord / dictionarySuggestions。历史 main.js
//   只对 linkURL 做了 isSafeUrl，其余字段直接信任：
//     1) selectionText / misspelledWord / 拼写建议被原样塞进原生 Menu 的 label：
//        超长选择文本撑爆菜单，CR/LF/制表符/RTL/ANSI 控制字符在菜单里伪造多行、
//        仿冒菜单项做视觉欺骗；
//     2) dictionarySuggestions 是网页 / 词典给的字符串数组，没有数量与长度上限，
//        可灌几百条超长建议刷菜单；misspelledWord 还会进
//        addWordToSpellCheckerDictionary 造成持久词典投毒；
//     3) srcURL / frameURL 只用于审计，若含控制字符 / 超长，会污染安全日志；
//     4) linkURL 除协议外还可能是 javascript: 配合“在新标签页打开”，或含凭据段。
//
// 本内核把 params 归一成一组“可安全使用”的字段，main.js 只用净化后的值建菜单。
// 所有函数纯逻辑、不碰 Electron API。

const SAFE_MENU_SCHEMES = new Set(['http:', 'https:']);

const MAX_MENU_URL_CHARS = 4096;
const MAX_MENU_TEXT_CHARS = 200;   // 菜单项展示文本上限
const MAX_MENU_WORD_CHARS = 64;    // 单词 / 拼写建议词条上限
const MAX_SUGGESTIONS = 6;         // 与 UI 展示条数一致

function schemeOf(rawUrl) {
  if (typeof rawUrl !== 'string' || !rawUrl) return '';
  const m = /^([a-z][a-z0-9+.-]*:)/i.exec(rawUrl.trim());
  return m ? m[1].toLowerCase() : '';
}

// hasControlChar 报告字符串是否含 C0 控制字符、DEL、Unicode 行/段分隔符或 BOM。
// 普通空白（空格 / Tab）不算，但 CR/LF 算（它们能在菜单里折行伪造条目）。
function hasControlChar(s) {
  if (typeof s !== 'string') return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return true;
    if (c === 0x2028 || c === 0x2029 || c === 0xfeff) return true;
  }
  return false;
}

// safeMenuUrl 校验要用于“打开链接 / 复制链接”的 URL：必须是 http(s)、无控制字符、
// 不超长。返回 { ok, url }；不做静默改写。
function safeMenuUrl(rawUrl) {
  if (typeof rawUrl !== 'string') return { ok: false, url: '' };
  const url = rawUrl.trim();
  if (!url) return { ok: false, url: '' };
  if (url.length > MAX_MENU_URL_CHARS) return { ok: false, url: '' };
  if (hasControlChar(url)) return { ok: false, url: '' };
  if (!SAFE_MENU_SCHEMES.has(schemeOf(url))) return { ok: false, url: '' };
  try {
    const u = new URL(url);
    if (u.origin === 'null') return { ok: false, url: '' };
  } catch {
    return { ok: false, url: '' };
  }
  return { ok: true, url };
}

// cleanMenuText 净化用于菜单 label 的文本：折叠连续空白、去掉所有控制字符、限长。
// 与 URL 不同，展示文本可以“清洗后使用”，因为它不触发任何动作，只显示。
function cleanMenuText(raw, maxChars) {
  const max = typeof maxChars === 'number' && maxChars > 0 ? maxChars : MAX_MENU_TEXT_CHARS;
  if (typeof raw !== 'string') return '';
  let out = '';
  let lastSpace = false;
  for (let i = 0; i < raw.length && out.length < max; i++) {
    const c = raw.charCodeAt(i);
    if (c < 0x20 || c === 0x7f || c === 0x2028 || c === 0x2029 || c === 0xfeff) {
      // 控制字符统一压成一个空格（含 CR/LF/Tab），防止折行伪造菜单项。
      if (!lastSpace && out) { out += ' '; lastSpace = true; }
      continue;
    }
    if (c === 0x20 || c === 0x09) {
      if (!lastSpace && out) { out += ' '; lastSpace = true; }
      continue;
    }
    out += raw[i];
    lastSpace = false;
  }
  return out.trim().slice(0, maxChars);
}

// isDictionaryWord 判定一个词条是否适合写入本地拼写词典 / 用于替换：
// 非空、不含空白与控制字符、长度受限、仅含常见单词字符（含中文等字母）。
function isDictionaryWord(word) {
  if (typeof word !== 'string') return false;
  const w = word.trim();
  if (!w || w.length > MAX_MENU_WORD_CHARS) return false;
  if (/\s/.test(w)) return false;
  if (hasControlChar(w)) return false;
  // 拒绝明显的标记 / 脚本片段，避免词典被灌入可执行形态字符串。
  if (/[<>{}]/.test(w)) return false;
  return true;
}

// cleanSuggestions 净化拼写建议数组：逐词校验、去重、限量、限长。
function cleanSuggestions(rawList) {
  const out = [];
  const seen = new Set();
  if (!Array.isArray(rawList)) return out;
  for (const item of rawList) {
    if (out.length >= MAX_SUGGESTIONS) break;
    if (!isDictionaryWord(item)) continue;
    const w = item.trim();
    if (seen.has(w)) continue;
    seen.add(w);
    out.push(w);
  }
  return out;
}

// evaluateContextMenu 是 main.js 在 context-menu 里调用的总入口。
// 输入 Electron params，返回一组可直接安全使用的字段：
// {
//   linkUrl,            // 仅当可安全打开/复制时给出，否则 ''
//   canUseLink,
//   selectionText,      // 清洗后的选中文本（用于 label / 搜索），'' 表示无
//   hasSelection,
//   isEditable,
//   misspelledWord,     // 仅当是合法词典词时给出
//   suggestions,        // 净化后的建议数组
//   reasons,            // 命中的净化原因（审计用）
// }
function evaluateContextMenu(params) {
  const p = params && typeof params === 'object' ? params : {};
  const reasons = [];

  const link = safeMenuUrl(p.linkURL);
  if (typeof p.linkURL === 'string' && p.linkURL && !link.ok) {
    reasons.push('unsafe-link-url');
  }

  let selectionText = '';
  if (typeof p.selectionText === 'string' && p.selectionText) {
    selectionText = cleanMenuText(p.selectionText, MAX_MENU_TEXT_CHARS);
    if (selectionText.length === 0) reasons.push('selection-dropped');
    if (p.selectionText.length > MAX_MENU_TEXT_CHARS) reasons.push('selection-truncated');
  }

  let misspelledWord = '';
  let suggestions = [];
  if (p.isEditable && typeof p.misspelledWord === 'string' && p.misspelledWord) {
    if (isDictionaryWord(p.misspelledWord)) {
      misspelledWord = p.misspelledWord.trim();
    } else {
      reasons.push('misspelled-word-dropped');
    }
    suggestions = cleanSuggestions(p.dictionarySuggestions);
    if (Array.isArray(p.dictionarySuggestions) &&
        p.dictionarySuggestions.length > suggestions.length) {
      reasons.push('suggestions-filtered');
    }
  }

  return {
    linkUrl: link.url,
    canUseLink: link.ok,
    selectionText,
    hasSelection: selectionText.length > 0,
    isEditable: p.isEditable === true,
    misspelledWord,
    suggestions,
    reasons,
  };
}

module.exports = {
  SAFE_MENU_SCHEMES,
  MAX_MENU_URL_CHARS,
  MAX_MENU_TEXT_CHARS,
  MAX_MENU_WORD_CHARS,
  MAX_SUGGESTIONS,
  schemeOf,
  hasControlChar,
  safeMenuUrl,
  cleanMenuText,
  isDictionaryWord,
  cleanSuggestions,
  evaluateContextMenu,
};
