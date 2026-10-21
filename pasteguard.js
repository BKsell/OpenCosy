'use strict';

// pasteguard.js —— 地址栏 / 输入框粘贴内容的安全裁决内核。
//
// 威胁模型：用户“复制来的链接”并不总是纯文本。攻击面有三类：
//
//   1. 隐形字符：零宽空格(U+200B)、BOM(U+FEFF)、软连字符(U+00AD) 藏在域名里，
//      地址栏肉眼看不见，却改变实际主机名或触发奇怪解析；
//   2. 双向控制字符：U+202E(RLO) 把 https://‮evil.xpx 之类的字符串在视觉上
//      翻转成 https://xpx.live，用户看到的顺序与真实导航顺序相反；
//   3. 富文本假链接：从网页/邮件复制的是 <a href="真实地址">显示成另一个网址
//      的文字</a>，或 href 直接是 javascript:/data:/file:；
//   4. 同形字（homograph）：西里尔 а/е/о/р/с 混进拉丁域名冒充正规站点。
//
// 本模块纯函数、不触 DOM/网络。为避免正则在复杂 unicode 上的误判，全部用
// 码点扫描与字符串 indexOf 实现。

// 需要从粘贴 URL 中剥离的隐形/格式字符码点。
const INVISIBLE_CODEPOINTS = (() => {
  const s = new Set();
  const addRange = (lo, hi) => {
    for (let c = lo; c <= hi; c++) s.add(c);
  };
  addRange(0x200b, 0x200f); // 零宽空格/连字/方向标记
  addRange(0x202a, 0x202e); // LRE/RLE/PDF/LRO/RLO 双向控制
  s.add(0x2060); // WJ
  s.add(0x2066); s.add(0x2067); s.add(0x2068); // LRI/RLI/FSI
  s.add(0x2069); // PDI
  s.add(0xfeff); // BOM / ZWNBSP
  s.add(0x00ad); // 软连字符
  s.add(0x180e); // 蒙古文元音分隔符
  return s;
})();

// 一旦出现就不应自动导航、必须人工确认的双向覆盖类字符。
const HARD_BIDI_CODEPOINTS = new Set([0x202a, 0x202b, 0x202c, 0x202d, 0x202e]);

// 常见西里尔 -> 拉丁视觉同形映射（仅用于给出“疑似真身”提示，不做自动改写导航）。
const CYRILLIC_CONFUSABLE = {
  0x0430: 'a', 0x0435: 'e', 0x043e: 'o', 0x0440: 'p', 0x0441: 'c',
  0x0443: 'y', 0x0445: 'x', 0x0430: 'a', 0x0456: 'i', 0x0458: 'j',
  0x0432: 'b', 0x043d: 'h', 0x043a: 'k', 0x043c: 'm', 0x0442: 't',
  0x0410: 'A', 0x0412: 'B', 0x0421: 'C', 0x0415: 'E', 0x041d: 'H',
  0x041a: 'K', 0x041c: 'M', 0x041e: 'O', 0x0420: 'P', 0x0422: 'T',
  0x0425: 'X',
};
// 希腊字母里与拉丁形似的少量字符。
const GREEK_CONFUSABLE = {
  0x03bf: 'o', 0x039f: 'O', 0x03b1: 'a', 0x0391: 'A',
  0x03b2: 'b', 0x0392: 'B', 0x03b5: 'e', 0x0395: 'E',
};

function codePoints(str) {
  return Array.from(str);
}

// 剥离隐形字符，返回 { text, removed, hadBidi }。普通空白（空格/tab/换行）保留，
// 交由调用方根据场景决定如何处理。
function stripInvisible(str) {
  let removed = 0;
  let hadBidi = false;
  const out = [];
  for (const ch of codePoints(str)) {
    const cp = ch.codePointAt(0);
    if (HARD_BIDI_CODEPOINTS.has(cp)) {
      hadBidi = true;
      removed++;
      continue;
    }
    if (INVISIBLE_CODEPOINTS.has(cp)) {
      removed++;
      continue;
    }
    out.push(ch);
  }
  return { text: out.join(''), removed, hadBidi };
}

function isAsciiWhitespace(cp) {
  return cp === 9 || cp === 10 || cp === 13 || cp === 32;
}

// 从疑似 URL 文本的主机部分取出 host（仅在明确 http(s):// 前缀时）。
function hostOf(urlLike) {
  const lower = urlLike.toLowerCase();
  let rest;
  if (lower.startsWith('https://')) rest = urlLike.slice(8);
  else if (lower.startsWith('http://')) rest = urlLike.slice(7);
  else return null;
  let end = rest.length;
  for (let i = 0; i < rest.length; i++) {
    const cp = rest.charCodeAt(i);
    if (cp === 47 || cp === 63 || cp === 35 || cp === 58 || cp === 92) {
      end = i;
      break;
    }
  }
  return rest.slice(0, end);
}

// 扫描主机名中的非拉丁同形字母，返回 { count, suggestion, scripts:[...] }。
function scanHostConfusables(host) {
  if (!host) return { count: 0, suggestion: host, scripts: [] };
  let count = 0;
  const scripts = new Set();
  const suggest = [];
  for (const ch of codePoints(host)) {
    const cp = ch.codePointAt(0);
    if (CYRILLIC_CONFUSABLE[cp] !== undefined) {
      count++;
      scripts.add('cyrillic');
      suggest.push(CYRILLIC_CONFUSABLE[cp]);
    } else if (GREEK_CONFUSABLE[cp] !== undefined) {
      count++;
      scripts.add('greek');
      suggest.push(GREEK_CONFUSABLE[cp]);
    } else {
      suggest.push(ch);
    }
  }
  return { count, suggestion: suggest.join(''), scripts: Array.from(scripts) };
}

// sanitizePastedUrl 处理地址栏粘贴。返回：
//   status: 'ok'（可直接使用）| 'cleaned'（剥离过隐形字符）|
//           'suspicious'（需提示）| 'blocked'（含双向覆盖，禁止自动导航）
//   text: 清洗结果；reasons: 命中信号。
function sanitizePastedUrl(raw) {
  const reasons = [];
  if (typeof raw !== 'string') {
    return { status: 'blocked', text: '', reasons: ['not-a-string'] };
  }
  let text = raw;

  // 记录首部噪声（前导空白/换行），防止 “\nhttps://evil.com” 这种把真实
  // 链接藏在第一行之后的粘贴。
  let leadNoise = 0;
  while (leadNoise < text.length && isAsciiWhitespace(text.charCodeAt(leadNoise))) leadNoise++;
  if (leadNoise > 0) reasons.push('leading-noise');

  const stripped = stripInvisible(text);
  if (stripped.hadBidi) {
    return { status: 'blocked', text: stripped.text.trim(), reasons: ['bidi-override'] };
  }
  if (stripped.removed > 0) reasons.push('invisible-stripped');
  text = stripped.text;

  // 内部换行/制表符：URL 不允许跨行，出现说明是“整段文本里夹链接”，
  // 地址栏不应整段导航。
  let innerNewline = false;
  let innerSpace = false;
  const t = text.trim();
  for (let i = 0; i < t.length; i++) {
    const cp = t.charCodeAt(i);
    if (cp === 10 || cp === 13) innerNewline = true;
    if (cp === 9) innerSpace = true;
  }
  if (innerNewline) reasons.push('embedded-newline');
  if (innerSpace) reasons.push('embedded-tab');

  const host = hostOf(t);
  if (host) {
    if (host.includes(' ')) reasons.push('space-in-host');
    const conf = scanHostConfusables(host);
    if (conf.count > 0) {
      reasons.push('homograph-host');
    }
  }

  text = t;
  let status = 'ok';
  if (reasons.includes('homograph-host') || reasons.includes('embedded-newline') ||
      reasons.includes('space-in-host') || reasons.includes('embedded-tab')) {
    status = 'suspicious';
  } else if (reasons.length > 0) {
    status = 'cleaned';
  }
  return { status, text, reasons, removed: stripped.removed };
}

// —— 极简 <a> 标签扫描（不使用正则） ——

function indexOfCI(s, sub, from) {
  return s.toLowerCase().indexOf(sub.toLowerCase(), from);
}

// 从一段标签内部文本（<a …> 中 … 之前）用字符扫描取属性值，支持单/双引号。
function readAttr(tagText, attr) {
  const needle = attr;
  let i = 0;
  while (i < tagText.length) {
    const at = indexOfCI(tagText, needle, i);
    if (at < 0) return null;
    const before = at === 0 ? ' ' : tagText[at - 1];
    if (before !== ' ' && before !== '\t' && before !== '\n' && before !== '\r') {
      i = at + 1;
      continue;
    }
    let j = at + needle.length;
    while (j < tagText.length && (tagText[j] === ' ' || tagText[j] === '\t')) j++;
    if (tagText[j] !== '=') { i = at + 1; continue; }
    j++;
    while (j < tagText.length && (tagText[j] === ' ' || tagText[j] === '\t')) j++;
    const q = tagText[j];
    if (q === '"' || q === "'") {
      const end = tagText.indexOf(q, j + 1);
      if (end < 0) return null;
      return tagText.slice(j + 1, end);
    }
    const start = j;
    while (j < tagText.length && tagText[j] !== ' ' && tagText[j] !== '>' && tagText[j] !== '\t') j++;
    return tagText.slice(start, j);
  }
  return null;
}

function stripSimpleTags(s) {
  let out = '';
  let i = 0;
  while (i < s.length) {
    if (s[i] === '<') {
      const gt = s.indexOf('>', i);
      if (gt < 0) { i = s.length; continue; }
      i = gt + 1;
    } else {
      out += s[i];
      i++;
    }
  }
  return out;
}

function decodeBasicEntities(s) {
  return s
    .split('&amp;').join('&')
    .split('&lt;').join('<')
    .split('&gt;').join('>')
    .split('&quot;').join('"')
    .split('&#39;').join("'")
    .split('&nbsp;').join(' ');
}

function dangerousHrefScheme(href) {
  const h = href.trim().toLowerCase();
  const schemes = ['javascript:', 'data:', 'vbscript:', 'file:', 'about:', 'blob:'];
  for (const sc of schemes) {
    if (h.startsWith(sc)) return sc.slice(0, -1);
  }
  return null;
}

// analyzeAnchorHTML 扫描富文本剪贴板 HTML 中的链接，返回逐条裁决。
// links: [{href,label,reasons[]}]；verdict: 'ok'|'suspicious'|'blocked'。
function analyzeAnchorHTML(html) {
  const result = { verdict: 'ok', links: [], anchorCount: 0 };
  if (typeof html !== 'string' || html === '') return result;
  let i = 0;
  while (i < html.length) {
    const open = indexOfCI(html, '<a', i);
    if (open < 0) break;
    // 必须是标签起点（下一个字符为空白或 >），避免命中 <article。
    const after = html[open + 2];
    if (after !== ' ' && after !== '\t' && after !== '\n' && after !== '\r' && after !== '>') {
      i = open + 2;
      continue;
    }
    const gt = html.indexOf('>', open);
    if (gt < 0) break;
    const tag = html.slice(open, gt);
    const close = indexOfCI(html, '</a>', gt);
    const innerEnd = close < 0 ? html.length : close;
    const label = decodeBasicEntities(stripSimpleTags(html.slice(gt + 1, innerEnd))).trim();
    const href = readAttr(tag, 'href');
    result.anchorCount++;

    const link = { href: href || '', label, reasons: [] };
    if (href) {
      const ds = dangerousHrefScheme(href);
      if (ds) link.reasons.push('dangerous-href:' + ds);
      const hrefHost = hostOf(href.trim());
      const labelHost = label ? hostOf(stripInvisible(label).text.trim()) : null;
      if (hrefHost && labelHost) {
        let a = hrefHost.toLowerCase();
        let b = labelHost.toLowerCase();
        if (a.endsWith('.')) a = a.slice(0, -1);
        if (b.endsWith('.')) b = b.slice(0, -1);
        if (a !== b && !a.endsWith('.' + b) && !b.endsWith('.' + a)) {
          link.reasons.push('label-href-mismatch');
        }
      }
      const conf = scanHostConfusables(hrefHost || '');
      if (conf.count > 0) {
        link.reasons.push('homograph-host');
        link.suggestedHost = conf.suggestion;
      }
    }
    if (link.reasons.some(r => r.startsWith('dangerous-href'))) result.verdict = 'blocked';
    else if (link.reasons.length > 0 && result.verdict !== 'blocked') result.verdict = 'suspicious';
    result.links.push(link);

    i = close < 0 ? innerEnd : close + 4;
  }
  return result;
}

// decideClipboardPaste 综合文本 + HTML 给出粘贴裁决，供地址栏调用。
//   优先级：HTML 危险脚本协议 > 文本双向覆盖 > 假链接/同形字 > 隐形清洗。
function decideClipboardPaste(payload) {
  const text = payload && typeof payload.text === 'string' ? payload.text : '';
  const html = payload && typeof payload.html === 'string' ? payload.html : '';
  const textVerdict = sanitizePastedUrl(text);
  const htmlVerdict = analyzeAnchorHTML(html);

  const reasons = textVerdict.reasons.slice();
  let status = textVerdict.status;
  let finalText = textVerdict.text;
  const links = [];

  if (htmlVerdict.anchorCount > 0) {
    for (const l of htmlVerdict.links) {
      reasons.push(...l.reasons);
      links.push(l);
    }
    if (htmlVerdict.verdict === 'blocked') status = 'blocked';
    if (htmlVerdict.verdict === 'suspicious' && status !== 'blocked') status = 'suspicious';
    // 富文本里只有一个安全链接时，建议用其 href 作为导航目标。
    if (htmlVerdict.links.length === 1 && htmlVerdict.verdict === 'ok' && htmlVerdict.links[0].href) {
      finalText = htmlVerdict.links[0].href;
    }
  }
  return { status, text: finalText, reasons: Array.from(new Set(reasons)), links };
}

module.exports = {
  INVISIBLE_CODEPOINTS,
  CYRILLIC_CONFUSABLE,
  stripInvisible,
  hostOf,
  scanHostConfusables,
  sanitizePastedUrl,
  readAttr,
  stripSimpleTags,
  analyzeAnchorHTML,
  decideClipboardPaste,
};
