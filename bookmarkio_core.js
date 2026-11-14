
const { JSON_MAX_DEPTH, JSON_MAX_ELEMENTS, parseBoundedJSON } = require('./boundedjson_core');
const { MAX_BOOKMARKS_IMPORT, MAX_IMPORT_FILE_BYTES, safeBookmarkURL, normalizeBookmark } = require('./bookmarkbase_core');
const { parseHTMLBookmarks, buildExportHTML } = require('./bookmarkhtml_core');
'use strict';

// bookmarkio.js —— 书签的导入 / 导出。
//
// 设计要点（全部是真实安全边界，不是装饰）：
//  1. 导入的书签文件来自任意第三方浏览器导出，本质是“不可信外部数据”：
//     - 只允许 http/https 两种 scheme，javascript:/data:/file: 一律丢弃，
//       防止书签栏里藏一个点击即执行脚本的条目；
//     - 数量、标题长度、URL 长度全部设上限，挡住用超大文件撑内存/存储的恶意导出；
//     - JSON 导入不允许顶层非数组、不做原型合并，重复 URL 自动去重。
//  2. HTML 解析不引入任何 HTML 解析器，直接用严格正则抽取 <DT><A HREF=...>，
//     属性值只接受双引号包裹的形式；浏览器书签导出天然是这种规整结构。
//  3. 导出的 HTML 对标题做实体转义，避免标题里的 "</a>" 之类破坏文件结构。

// 只接受 http(s) 链接，且必须带主机名。

// normalizeBookmark 把任意一条原始记录压成 { url, title, addedDate }；
// 不合法的条目返回 null。

function parseJSONBookmarks(text) {
  let data;
  try {
    data = parseBoundedJSON(text);
  } catch (e) {
    throw new Error(`JSON 解析失败：${e.message || '不是有效的书签文件'}`);
  }
  if (!Array.isArray(data)) {
    throw new Error('JSON 顶层必须是书签数组');
  }
  if (data.length > MAX_BOOKMARKS_IMPORT) {
    throw new Error(`书签数量超过上限（最多 ${MAX_BOOKMARKS_IMPORT} 条，收到 ${data.length} 条）`);
  }
  const out = [];
  for (const item of data) {
    const bm = normalizeBookmark(item);
    if (bm) out.push(bm);
  }
  return out;
}

// parseHTMLBookmarks 解析 Netscape Bookmark File Format
// （Chrome / Edge / Firefox 的“导出书签”都是这个格式）。
// 只认 <DT><A HREF="...">标题</A> 这一种形态，忽略文件夹层级——
// 导入后统一拍平，和 OpenCosy 现有扁平书签模型一致。

// parseBookmarkFile 按内容自动识别 JSON 或 Netscape HTML。
function parseBookmarkFile(buffer) {
  if (!Buffer.isBuffer(buffer)) throw new Error('无效的文件内容');
  if (buffer.length === 0) throw new Error('书签文件为空');
  if (buffer.length > MAX_IMPORT_FILE_BYTES) {
    throw new Error(`书签文件过大（上限 ${MAX_IMPORT_FILE_BYTES / 1024 / 1024}MiB）`);
  }
  const text = buffer.toString('utf8').replace(/^﻿/, '');
  const head = text.slice(0, 4096).toLowerCase();
  if (head.includes('<!doctype netscape-bookmark') || head.includes('<netscape-bookmark')) {
    return { format: 'html', bookmarks: parseHTMLBookmarks(text) };
  }
  const trimmed = text.trimStart();
  if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
    // 兼容 { bookmarks: [...] } 包装。
    if (trimmed.startsWith('{')) {
      const parsed = parseBoundedJSON(text);
      if (!parsed || !Array.isArray(parsed.bookmarks)) {
        throw new Error('JSON 对象必须包含 bookmarks 数组');
      }
      return { format: 'json', bookmarks: parseJSONBookmarks(JSON.stringify(parsed.bookmarks)) };
    }
    return { format: 'json', bookmarks: parseJSONBookmarks(text) };
  }
  // 没带格式头但确实含锚点的，按 HTML 兜试一次。
  if (/<a\s+[^>]*href\s*=/i.test(head)) {
    return { format: 'html', bookmarks: parseHTMLBookmarks(text) };
  }
  throw new Error('无法识别的书签文件格式（支持 JSON 或 Netscape 书签 HTML）');
}

// mergeBookmarks 把新书签并进现有列表：URL 去重（保留已存在的标题/日期），
// 返回合并后的完整列表与实际新增条数。
function mergeBookmarks(existing, incoming) {
  const seen = new Set();
  const merged = [];
  for (const bm of existing) {
    const norm = normalizeBookmark(bm);
    if (!norm || seen.has(norm.url)) continue;
    seen.add(norm.url);
    merged.push(norm);
  }
  let added = 0;
  for (const bm of incoming) {
    const norm = normalizeBookmark(bm);
    if (!norm || seen.has(norm.url)) continue;
    seen.add(norm.url);
    merged.push(norm);
    added++;
    if (merged.length >= MAX_BOOKMARKS_IMPORT) break;
  }
  return { merged, added };
}

// buildExportJSON 生成 OpenCosy 自有 JSON 导出。
function buildExportJSON(bookmarks) {
  return JSON.stringify(
    {
      format: 'opencosy-bookmarks',
      version: 1,
      exportedAt: new Date().toISOString(),
      bookmarks: bookmarks.map(b => ({
        url: b.url,
        title: b.title || b.url,
        addedDate: b.addedDate || null,
      })),
    },
    null,
    2
  );
}

// buildExportHTML 生成兼容 Chrome/Firefox 的 Netscape 书签 HTML。

module.exports = {
  MAX_BOOKMARKS_IMPORT,
  MAX_IMPORT_FILE_BYTES,
  JSON_MAX_DEPTH,
  JSON_MAX_ELEMENTS,
  parseBoundedJSON,
  safeBookmarkURL,
  parseBookmarkFile,
  mergeBookmarks,
  buildExportJSON,
  buildExportHTML,
};
