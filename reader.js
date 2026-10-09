'use strict';

// reader.js —— 阅读模式（Reader Mode）的“抽取与净化”纯内核。
//
// 解决的问题：
//   现代浏览器普遍提供阅读模式：去掉导航 / 广告 / 相关推荐，只保留正文，并用统一字号、
//   行距重新排版。OpenCosy 此前完全没有这个能力。
//
// 安全模型（为什么它不会把恶意网页的脚本带进阅读页）：
//   1) 抽取发生在“原网页自己的 DOM”里，但只读不写：遍历真实节点，挑出正文容器；
//   2) 输出不是 HTML 字符串，而是一棵只含 {tag,text,href,children} 的纯数据树——
//      标签必须命中白名单，文本一律走 textContent，属性除链接 href / 图片 src 外全部丢弃，
//      因此 onerror、onclick、javascript: 链接、<script> 等根本没有位置可放；
//   3) 阅读页（cosy://reader）拿到的是 JSON，用 createElement + textContent 重建节点，
//      全程不碰 innerHTML / insertAdjacentHTML，DOM 解析器永远不会把数据当代码执行。
//
// 本文件全部是纯函数 / 常量，便于用 node:test 在没有 Electron 与 DOM 的环境下验证；
// 真正注入网页执行的脚本由 buildReaderExtractScript() 用这些同名函数的源码拼装，保证
// “被测的判定逻辑”与“线上跑的判定逻辑”是同一份实现，不存在两套逻辑漂移。
//
// 实现约束：按项目要求不使用正则表达式。文本判定全部基于字符串方法 / 字符比较。

// 抽取阶段直接忽略、不进入任何候选与输出的标签（脚本、样式、交互控件、可嵌入对象）。
const SKIP_TAGS = new Set([
  'script', 'style', 'noscript', 'template', 'iframe', 'frame', 'object', 'embed',
  'applet', 'svg', 'canvas', 'form', 'input', 'button', 'select', 'textarea', 'option',
  'dialog', 'details', 'summary',
]);

// 打分阶段视为“噪音容器”的标签：页眉 / 导航 / 页脚 / 侧栏 / 广告槽，不参与最佳正文选举。
const NOISE_TAGS = new Set([
  'nav', 'aside', 'footer', 'header', 'address', 'menu',
]);

// 允许出现在最终阅读树里的“块级”标签。其余容器（div/section 等）不输出自身，
// 只把其中符合白名单的子节点提升上来，避免把版面 class/style 结构带进来。
const OUTPUT_BLOCK_TAGS = new Set([
  'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
  'blockquote', 'pre', 'ul', 'ol', 'li',
  'figure', 'figcaption', 'img', 'hr', 'table', 'thead', 'tbody', 'tr', 'th', 'td',
]);

// 允许在段落内保留的“内联”标签。链接只保留安全 href，其余内联只用于加粗 / 斜体 / 等宽。
const OUTPUT_INLINE_TAGS = new Set([
  'strong', 'b', 'em', 'i', 'code', 'kbd', 'samp', 'var', 'mark', 'small', 'sub', 'sup',
  'a', 'br', 'span', 'time', 'cite', 'q', 'abbr',
]);

// 可作为“正文容器”参与打分的标签。article/main 天然优先，语义/通用块容器作为候选。
const CONTAINER_TAGS = new Set([
  'article', 'main', 'section', 'div', 'td',
]);

const READER_MAX_NODES = 4000;       // 最终阅读树节点上限，防止超长页面把 IPC 撑爆
const READER_MAX_DEPTH = 24;         // 阅读树最大嵌套深度，挡异常深 DOM
const READER_MAX_TEXT_CHARS = 200000; // 正文总字符上限
const READER_MAX_LINK_CHARS = 2000;  // 单个链接锚文本上限
const READER_MIN_ARTICLE_CHARS = 200; // 低于该长度认为“没有可抽取正文”
const READER_WPM = 450;              // 中文为主的阅读速度（字/分钟）估算

function isWhitespaceCode(code) {
  return code === 32 || code === 9 || code === 10 || code === 11 || code === 12 ||
    code === 13 || code === 0x85 || code === 0xa0 || code === 0x3000;
}

// collapseSpaces 把连续空白（含中文全角空格 / 不间断空格）折叠为单个普通空格，
// 不使用正则。用于抽取时把跨节点换行的文本归一。
function collapseSpaces(s) {
  s = String(s == null ? '' : s);
  let out = '';
  let pending = false;
  for (let i = 0; i < s.length; i++) {
    if (isWhitespaceCode(s.charCodeAt(i))) {
      pending = true;
      continue;
    }
    if (pending) {
      if (out !== '') out += ' ';
      pending = false;
    }
    out += s[i];
  }
  if (pending && out !== '') out += ' ';
  return out;
}

function normalizeTagName(nodeName) {
  return String(nodeName == null ? '' : nodeName).toLowerCase();
}

function isSkippable(tag) {
  return SKIP_TAGS.has(tag);
}

function isNoise(tag) {
  return NOISE_TAGS.has(tag);
}

function isOutputBlock(tag) {
  return OUTPUT_BLOCK_TAGS.has(tag);
}

function isOutputInline(tag) {
  return OUTPUT_INLINE_TAGS.has(tag);
}

function isContainer(tag) {
  return CONTAINER_TAGS.has(tag);
}

function elementText(el) {
  return el && typeof el.textContent === 'string' ? el.textContent : '';
}

// safeHref 只放行绝对的 http/https 链接：挡掉 javascript:/data:/vbscript: 等危险
// scheme、协议相对 URL（//host），以及无 scheme 的相对 / 纯锚点链接。阅读页跑在
// cosy: 源上，不保留原页面基址，相对链接无法安全解析成正确目标，统一降级为纯文本。
// 返回空字符串表示该链接不保留为可点链接。
function safeHref(raw) {
  let href = String(raw == null ? '' : raw).trim();
  if (href === '') return '';
  // 去掉控制字符，防止用换行 / Tab 在视觉上混淆 scheme。
  let cleaned = '';
  for (let i = 0; i < href.length; i++) {
    const code = href.charCodeAt(i);
    if (code <= 0x20 || code === 0x7f) continue;
    cleaned += href[i];
  }
  href = cleaned;
  if (href.charCodeAt(0) === 0x2f && href.charCodeAt(1) === 0x2f) return ''; // 协议相对 URL
  const colon = href.indexOf(':');
  if (colon < 0) return ''; // 无 scheme 的相对链接 / 纯锚点
  const scheme = href.slice(0, colon).toLowerCase();
  return scheme === 'http' || scheme === 'https' ? href : '';
}

// safeImageSrc 与 safeHref 同口径（阅读页图片同样只接受绝对 http/https）。
function safeImageSrc(raw) {
  return safeHref(raw);
}

// linkDensity 返回容器文本中“位于链接内”的字符占比（0~1）。导航 / 相关阅读段落该值接近 1。
function linkDensity(linkTextLength, textLength) {
  if (!(textLength > 0)) return 0;
  const r = linkTextLength / textLength;
  return r > 1 ? 1 : r;
}

// 句读密度：中文逗号/句号/顿号/分号/问号/感叹号与英文逗号句号的占比线索，正文高于菜单。
function punctuationCount(text) {
  let n = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '，' || ch === '。' || ch === '、' || ch === '；' || ch === '?' ||
      ch === '！' || ch === '？' || ch === ',' || ch === '.' || ch === '!' || ch === ':') {
      n++;
    }
  }
  return n;
}

// scoreContainer 依据“候选摘要”给正文容器打分。入参是已经汇总好的纯数据（不依赖 DOM），
// 便于在测试里直接构造。linkDensity 越高越像链接农场，惩罚越重。
function scoreContainer(s) {
  if (!s) return -Infinity;
  const text = Math.max(0, s.textLength | 0);
  const paragraphs = Math.max(0, s.paragraphCount | 0);
  const density = linkDensity(s.linkTextLength | 0, text);
  const punct = punctuationCount(typeof s.textSample === 'string' ? s.textSample : '');
  let score = text;
  score += paragraphs * 40;
  score += Math.min(punct, 200) * 2;
  score -= density * text * 1.5;
  if (s.semanticArticle) score += 500; // <article>/<main> 明确语义，额外加权
  if (s.semanticMain) score += 300;
  if (s.noise) score -= 800;
  return Math.round(score);
}

// cleanTitle 清理文档标题里的站点后缀。保守做法：只在“分隔符后片段较短（像站名而非标题）”
// 时裁掉，且不使用正则。多个分隔符取最靠右、且右侧不超过 24 字的那一个。
function cleanTitle(rawTitle) {
  let title = collapseSpaces(rawTitle).trim();
  if (title === '') return '';
  const separators = [' | ', ' || ', ' - ', ' – ', ' — ', ' :: ', ' · ', ' » ', ' * '];
  let best = -1;
  for (const sep of separators) {
    const idx = title.lastIndexOf(sep);
    if (idx > 0) {
      const tailLen = title.length - (idx + sep.length);
      if (tailLen > 0 && tailLen <= 24 && idx > best) best = idx;
    }
  }
  if (best > 0) title = title.slice(0, best).trim();
  return title;
}

function estimateReadMinutes(textLength) {
  if (!(textLength > 0)) return 1;
  return Math.max(1, Math.round(textLength / READER_WPM));
}

function clampInt(v, lo, hi) {
  v = Number(v);
  if (!Number.isFinite(v)) v = lo;
  v = Math.floor(v);
  if (v < lo) return lo;
  if (v > hi) return hi;
  return v;
}

// buildReaderExtractScriptBody 返回常量 + 同名判定函数 + DOM 抽取体，末尾
// `return extractArticle(document)`，不含 IIFE 外壳，便于测试以 new Function 注入假 DOM。
function buildReaderExtractScriptBody() {
  return [
    'const SKIP_TAGS = new Set(' + JSON.stringify([...SKIP_TAGS]) + ');',
    'const NOISE_TAGS = new Set(' + JSON.stringify([...NOISE_TAGS]) + ');',
    'const OUTPUT_BLOCK_TAGS = new Set(' + JSON.stringify([...OUTPUT_BLOCK_TAGS]) + ');',
    'const OUTPUT_INLINE_TAGS = new Set(' + JSON.stringify([...OUTPUT_INLINE_TAGS]) + ');',
    'const CONTAINER_TAGS = new Set(' + JSON.stringify([...CONTAINER_TAGS]) + ');',
    'const READER_MAX_NODES = ' + READER_MAX_NODES + ';',
    'const READER_MAX_DEPTH = ' + READER_MAX_DEPTH + ';',
    'const READER_MAX_TEXT_CHARS = ' + READER_MAX_TEXT_CHARS + ';',
    'const READER_MAX_LINK_CHARS = ' + READER_MAX_LINK_CHARS + ';',
    'const READER_MIN_ARTICLE_CHARS = ' + READER_MIN_ARTICLE_CHARS + ';',
    'const READER_WPM = ' + READER_WPM + ';',
    isWhitespaceCode.toString() + ';',
    collapseSpaces.toString() + ';',
    normalizeTagName.toString() + ';',
    isSkippable.toString() + ';',
    isNoise.toString() + ';',
    isOutputBlock.toString() + ';',
    isOutputInline.toString() + ';',
    isContainer.toString() + ';',
    safeHref.toString() + ';',
    safeImageSrc.toString() + ';',
    linkDensity.toString() + ';',
    punctuationCount.toString() + ';',
    scoreContainer.toString() + ';',
    cleanTitle.toString() + ';',
    estimateReadMinutes.toString() + ';',
    clampInt.toString() + ';',
    IN_PAGE_EXTRACT_BODY,
    'return extractArticle(document);',
  ].join('\n');
}

// buildReaderExtractScript 生成注入“当前网页主世界”执行的抽取脚本（IIFE 包裹）。
function buildReaderExtractScript() {
  return '(() => {\n' + buildReaderExtractScriptBody() + '\n})();';
}

// IN_PAGE_EXTRACT_BODY 是真正依赖 DOM 的部分，仅运行在被抽取网页内。
// 它收集候选容器摘要 -> 选举最高分 -> 从当选节点导出安全树；找不到正文时回退为
// “全文所有合格段落”。绝不输出标签白名单之外的节点，绝不复制除 href/src 外的属性。
const IN_PAGE_EXTRACT_BODY = `
function summarizeContainer(el) {
  let textLength = 0, linkTextLength = 0, paragraphCount = 0;
  const paragraphs = el.getElementsByTagName('p');
  for (let i = 0; i < paragraphs.length; i++) paragraphCount++;
  const walk = el.ownerDocument.createTreeWalker(el, NodeFilter.SHOW_TEXT, null);
  let n = walk.nextNode();
  while (n) {
    const parent = n.parentElement ? normalizeTagName(n.parentElement.tagName) : '';
    if (!isSkippable(parent)) textLength += collapseSpaces(n.nodeValue || '').trim().length;
    n = walk.nextNode();
  }
  const anchors = el.getElementsByTagName('a');
  for (let i = 0; i < anchors.length; i++) {
    linkTextLength += (anchors[i].textContent || '').trim().length;
  }
  const tag = normalizeTagName(el.tagName);
  return {
    el, textLength, linkTextLength, paragraphCount,
    semanticArticle: tag === 'article',
    semanticMain: tag === 'main',
    noise: isNoise(tag),
    textSample: (el.textContent || '').slice(0, 4000),
  };
}

function chooseBestContainer(root) {
  const candidates = [];
  const seen = new Set();
  const consider = (el) => {
    if (!el || seen.has(el)) return;
    seen.add(el);
    candidates.push(summarizeContainer(el));
  };
  const semantic = root.querySelectorAll('article, main');
  for (let i = 0; i < semantic.length; i++) consider(semantic[i]);
  const blocks = root.querySelectorAll('section, div, td');
  for (let i = 0; i < blocks.length; i++) {
    const s = summarizeContainer(blocks[i]);
    if (s.paragraphCount >= 2 || s.textLength >= 400) candidates.push(s);
  }
  let best = null, bestScore = -Infinity;
  for (const s of candidates) {
    const score = scoreContainer(s);
    if (score > bestScore) { bestScore = score; best = s; }
  }
  return best && best.textLength >= READER_MIN_ARTICLE_CHARS ? best.el : null;
}

function makeNode(tag, text, href, children) {
  return { tag, text: text || '', href: href || '', children: children || [] };
}

function exportInline(el, state) {
  const tag = normalizeTagName(el.tagName);
  if (tag === 'a') {
    const href = safeHref(el.getAttribute('href'));
    const txt = (el.textContent || '').trim().slice(0, READER_MAX_LINK_CHARS);
    if (href) return makeNode('a', txt, href, []);
    return makeNode('span', txt, '', []);
  }
  const children = exportChildren(el, state);
  return makeNode(tag, '', '', children);
}

function exportChildren(el, state) {
  const out = [];
  for (const child of el.childNodes) {
    if (state.nodes >= READER_MAX_NODES || state.chars >= READER_MAX_TEXT_CHARS) break;
    if (child.nodeType === 3) {
      const t = collapseSpaces(child.nodeValue || '');
      if (t.trim() === '') continue;
      state.chars += t.length;
      out.push(makeNode('#text', t, '', []));
      continue;
    }
    if (child.nodeType !== 1) continue;
    const tag = normalizeTagName(child.tagName);
    if (isSkippable(tag) || isNoise(tag)) continue;
    if (tag === 'img') {
      const src = safeImageSrc(child.getAttribute('src'));
      if (src && state.nodes < READER_MAX_NODES) {
        state.nodes++;
        const alt = (child.getAttribute('alt') || '').trim().slice(0, 160);
        out.push(makeNode('img', alt, src, []));
      }
      continue;
    }
    if (tag === 'br') { state.nodes++; out.push(makeNode('br', '', '', [])); continue; }
    if (isOutputBlock(tag)) {
      const sub = exportElement(child, state);
      if (sub) out.push(sub);
      continue;
    }
    if (isOutputInline(tag)) {
      const node = exportInline(child, state);
      state.nodes++;
      out.push(node);
      continue;
    }
    // 未在白名单的容器：不输出自身，仅提升其合格子节点。
    for (const lifted of exportChildren(child, state)) out.push(lifted);
  }
  return out;
}

function exportElement(el, state) {
  const tag = normalizeTagName(el.tagName);
  const before = state.nodes;
  const children = exportChildren(el, state);
  const ownText = children.length === 0 ? (el.textContent || '').trim() : '';
  if (children.length === 0 && ownText === '' && tag !== 'hr' && tag !== 'img') return null;
  if (state.nodes === before && ownText === '' && tag !== 'hr') return null;
  state.nodes++;
  return makeNode(tag, ownText, '', children);
}

function fallbackParagraphs(root, state) {
  const out = [];
  const ps = root.querySelectorAll('p');
  for (let i = 0; i < ps.length; i++) {
    if (state.nodes >= READER_MAX_NODES || state.chars >= READER_MAX_TEXT_CHARS) break;
    const txt = (ps[i].textContent || '').trim();
    if (txt.length < 25) continue;
    state.nodes++;
    state.chars += txt.length;
    out.push(makeNode('p', txt, '', []));
  }
  return out;
}

function extractArticle(doc) {
  const root = doc.body || doc.documentElement;
  const state = { nodes: 0, chars: 0 };
  let content = [];
  const best = chooseBestContainer(root);
  if (best) content = exportChildren(best, state);
  if (content.length === 0) content = fallbackParagraphs(root, state);

  let byline = '';
  const author = doc.querySelector('meta[name="author"], meta[property="article:author"], [rel="author"]');
  if (author) byline = (author.getAttribute('content') || author.textContent || '').trim().slice(0, 120);

  let siteName = '';
  const site = doc.querySelector('meta[property="og:site_name"]');
  if (site) siteName = (site.getAttribute('content') || '').trim().slice(0, 120);

  const title = cleanTitle(doc.title || (doc.querySelector('h1') || {}).textContent || '');
  const plain = collapseSpaces(root.textContent || '').trim();
  let excerpt = plain.slice(0, 220);
  if (plain.length > 220) excerpt += '…';

  return {
    ok: state.chars >= READER_MIN_ARTICLE_CHARS || content.length > 0,
    title: title.slice(0, 300),
    byline,
    siteName,
    excerpt,
    url: (doc.location && doc.location.href) || '',
    wordCount: state.chars,
    readingTimeMinutes: estimateReadMinutes(state.chars),
    nodeCount: state.nodes,
    contentNodes: content,
  };
}
`;

module.exports = {
  SKIP_TAGS,
  NOISE_TAGS,
  OUTPUT_BLOCK_TAGS,
  OUTPUT_INLINE_TAGS,
  CONTAINER_TAGS,
  READER_MAX_NODES,
  READER_MAX_DEPTH,
  READER_MAX_TEXT_CHARS,
  READER_MAX_LINK_CHARS,
  READER_MIN_ARTICLE_CHARS,
  READER_WPM,
  isWhitespaceCode,
  collapseSpaces,
  normalizeTagName,
  isSkippable,
  isNoise,
  isOutputBlock,
  isOutputInline,
  isContainer,
  safeHref,
  safeImageSrc,
  linkDensity,
  punctuationCount,
  scoreContainer,
  cleanTitle,
  estimateReadMinutes,
  clampInt,
  buildReaderExtractScriptBody,
  buildReaderExtractScript,
};
