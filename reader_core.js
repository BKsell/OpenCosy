
const { SKIP_TAGS, NOISE_TAGS, OUTPUT_BLOCK_TAGS, OUTPUT_INLINE_TAGS, CONTAINER_TAGS, READER_MAX_NODES, READER_MAX_DEPTH, READER_MAX_TEXT_CHARS, READER_MAX_LINK_CHARS, READER_MIN_ARTICLE_CHARS, READER_WPM, isWhitespaceCode, collapseSpaces, normalizeTagName, isSkippable, isNoise, isOutputBlock, isOutputInline, isContainer, elementText, safeHref, safeImageSrc, linkDensity, punctuationCount, scoreContainer, cleanTitle, estimateReadMinutes, clampInt } = require('./readertext_core');
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
