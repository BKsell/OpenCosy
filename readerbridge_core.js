'use strict';

const { openSingletonTab } = require('./singletontab_core');

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

const READER_URL_SCHEMES = new Set(['http:', 'https:']);

function keepReaderUrl(value, baseUrl, maxChars) {
  if (typeof value !== 'string' || !value) return '';
  try {
    const parsed = new URL(value, baseUrl || undefined);
    if (!READER_URL_SCHEMES.has(parsed.protocol)) return '';
    const href = parsed.href;
    return href.length > maxChars ? '' : href;
  } catch {
    return '';
  }
}

function scrubReaderUrls(nodes, baseUrl) {
  for (const node of nodes) {
    if (node.href) {
      node.href = keepReaderUrl(node.href, baseUrl, d.readerCore.READER_MAX_LINK_CHARS);
      if (!node.href) delete node.href;
    }
    if (node.src) {
      node.src = keepReaderUrl(node.src, baseUrl, d.readerCore.READER_MAX_LINK_CHARS);
      if (!node.src) delete node.src;
    }
    if (node.children) scrubReaderUrls(node.children, baseUrl);
  }
  return nodes;
}

async function enterReaderMode() {
  const tab = d.tabs[d.currentTabIndex];
  const wc = tab && tab.view && !tab.view.webContents.isDestroyed() ? tab.view.webContents : null;
  if (!wc) return { ok: false, error: '当前标签不可用' };
  if (d.getUrlProtocol(tab.url) !== 'https:' && d.getUrlProtocol(tab.url) !== 'http:') {
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
  scrubReaderUrls(contentNodes, sourceUrl);
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
  return openSingletonTab(d, d.READER_PAGE_URL);
}

module.exports = { keepReaderUrl, scrubReaderUrls, sanitizeReaderNodes, enterReaderMode, sanitizeReaderArticle, clampReaderInt, openReaderTab, bindDeps };
