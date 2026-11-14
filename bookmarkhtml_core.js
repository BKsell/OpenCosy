'use strict';

const { MAX_BOOKMARKS_IMPORT, safeBookmarkURL, cleanTitle, stripTags, decodeHTMLEntities, escapeHTML } = require('./bookmarkbase_core');

function parseHTMLBookmarks(html) {
  const anchors = html.match(/<a\s+[^>]*href\s*=\s*"[^"]*"[^>]*>[\s\S]*?<\/a>/gi) || [];
  if (anchors.length > MAX_BOOKMARKS_IMPORT) {
    throw new Error(`书签数量超过上限（最多 ${MAX_BOOKMARKS_IMPORT} 条，文件中约 ${anchors.length} 条）`);
  }
  const out = [];
  const anchorRe = /<a\s+[^>]*href\s*=\s*"([^"]*)"[^>]*>([\s\S]*?)<\/a>/gi;
  let m;
  while ((m = anchorRe.exec(html)) !== null) {
    const url = safeBookmarkURL(m[1]);
    if (!url) continue;
    // 标题里的标签全部剥掉，只留纯文本；HTML 实体做最小集解码。
    const title = cleanTitle(decodeHTMLEntities(stripTags(m[2]))) || url;
    out.push({ url, title, addedDate: null });
  }
  if (out.length === 0) {
    throw new Error('文件中没有找到可导入的 http(s) 书签');
  }
  return out;
}

function buildExportHTML(bookmarks) {
  const lines = [
    '<!DOCTYPE NETSCAPE-Bookmark-file-1>',
    '<!-- This is an automatically generated file.',
    '     It will be read and overwritten.',
    '     DO NOT EDIT! Can be parsed by major browsers. -->',
    '<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">',
    '<TITLE>Bookmarks</TITLE>',
    '<H1>Bookmarks</H1>',
    '<DL><p>',
    `    <DT><H3 ADD_DATE="${Math.floor(Date.now() / 1000)}">OpenCosy 书签</H3>`,
    '    <DL><p>',
  ];
  for (const bm of bookmarks) {
    const url = safeBookmarkURL(bm.url);
    if (!url) continue;
    const title = escapeHTML(cleanTitle(bm.title) || url);
    const addDate = bm.addedDate && Number.isFinite(Date.parse(bm.addedDate))
      ? Math.floor(Date.parse(bm.addedDate) / 1000)
      : Math.floor(Date.now() / 1000);
    lines.push(`        <DT><A HREF="${escapeHTML(url)}" ADD_DATE="${addDate}">${title}</A>`);
  }
  lines.push('    </DL><p>', '</DL><p>');
  return lines.join('\r\n');
}

module.exports = { parseHTMLBookmarks, buildExportHTML };
