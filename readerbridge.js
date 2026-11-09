'use strict';

let d = {};

function bindDeps(next) {
  d = next;
}

function sanitizeReaderNodes(nodes, depth, budget) {
  const out = [];
  if (!Array.isArray(nodes) || depth > d.readerCore.READER_MAX_DEPTH) return out;
  for (const node of nodes) {
    if (budget.left <= 0) break;
    if (!node || typeof node !== 'object') continue;
    const tag = String(node.tag || '');
    if (!d.readerCore.OUTPUT_BLOCK_TAGS.has(tag) && !d.readerCore.OUTPUT_INLINE_TAGS.has(tag)) continue;
    const text = typeof node.text === 'string'
      ? node.text.slice(0, d.readerCore.READER_MAX_TEXT_CHARS) : '';
    const clean = { tag, text };
    if (typeof node.href === 'string' && node.href) clean.href = node.href.slice(0, d.readerCore.READER_MAX_LINK_CHARS);
    if (typeof node.src === 'string' && node.src) clean.src = node.src.slice(0, d.readerCore.READER_MAX_LINK_CHARS);
    if (typeof node.alt === 'string' && node.alt) clean.alt = node.alt.slice(0, 200);
    const kids = sanitizeReaderNodes(node.children, depth + 1, budget);
    if (kids.length) clean.children = kids;
    if (text || kids.length || clean.href || clean.src) {
      out.push(clean);
      budget.left -= 1;
    }
  }
  return out;
}

async function enterReaderMode() {
  const tab = d.tabs[d.currentTabIndex];
  const wc = tab && tab.view && !tab.view.webContents.isDestroyed() ? tab.view.webContents : null;
  if (!wc) return { ok: false, error: '当前标签不可用' };
  if (getUrlProtocol(tab.url) !== 'https:' && getUrlProtocol(tab.url) !== 'http:') {
    return { ok: false, error: '阅读模式仅支持 http(s) 网页' };
  }
  let raw = null;
  try {
    const script = d.readerCore.buildReaderExtractScript();
    raw = await Promise.race([
      wc.executeJavaScript(script, true),
      new Promise((_, reject) => setTimeout(() => reject(new Error('reader-timeout')), 4000)),
    ]);
  } catch {
    return { ok: false, error: '无法抽取当前页面' };
  }
  const article = sanitizeReaderArticle(raw, tab.url, tab.title);
  if (!article.ok || !article.contentNodes.length) return { ok: false, error: '未在该页找到可阅读的正文' };
  d.readerArticle = article;
  openReaderTab();
  return { ok: true };
}

function sanitizeReaderArticle(raw, sourceUrl, sourceTitle) {
  const budget = { left: d.readerCore.READER_MAX_NODES };
  const contentNodes = sanitizeReaderNodes(raw && raw.contentNodes, 0, budget);
  return {
    ok: !!(raw && raw.ok && contentNodes.length),
    title: String((raw && raw.title) || sourceTitle || '阅读模式').slice(0, 300),
    sourceUrl: String(sourceUrl || '').slice(0, d.readerCore.READER_MAX_LINK_CHARS),
    wordCount: clampReaderInt(raw && raw.wordCount, 10000000),
    minutes: clampReaderInt(raw && raw.minutes, 1000),
    contentNodes,
  };
}

function clampReaderInt(value, max) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.min(Math.floor(n), max);
}

function openReaderTab() {
  const existing = d.tabs.findIndex(t => t && t.url === d.READER_PAGE_URL);
  if (existing >= 0) {
    if (existing !== d.currentTabIndex) switchToTab(existing);
    return d.tabs[existing];
  }
  return createNewTab(d.READER_PAGE_URL);
}

module.exports = { sanitizeReaderNodes, enterReaderMode, sanitizeReaderArticle, clampReaderInt, openReaderTab, bindDeps };
