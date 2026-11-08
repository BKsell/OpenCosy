'use strict';

// bookmarkdedup.js —— 书签导入去重纯函数。
//
// 浏览器从 HTML/JSON 导入书签时，用户经常重复导入同一份导出文件，
// 结果 bookmarks 目录里同名同 URL 的条目堆了一片。这里把"这一批书签导入后
// 应该保留哪些"收敛成纯函数，调用方拿它跟现有书签集合做差。

// dedupeBookmarks 入参：
//   incoming  [{ title, url, folder }]
//   existing  [{ title, url }]  已存在的书签集合
//   keyFn     可选：自定义去重键，默认 `${title}\n${url}`
// 返回 { toAdd:[...], duplicates:[...] }
function dedupeBookmarks(incoming, existing, keyFn) {
  const seen = new Set();
  const existKeys = new Set();
  const fn = typeof keyFn === 'function' ? keyFn : (b) => `${b.title}\n${b.url}`;
  for (const e of Array.isArray(existing) ? existing : []) {
    existKeys.add(fn(e));
  }
  const toAdd = [];
  const duplicates = [];
  for (const b of Array.isArray(incoming) ? incoming : []) {
    const k = fn(b);
    if (existKeys.has(k) || seen.has(k)) {
      duplicates.push(b);
      continue;
    }
    seen.add(k);
    toAdd.push(b);
  }
  return { toAdd, duplicates };
}

// sanitizeBookmarkUrl 简单过滤明显不该当书签的 URL。
function sanitizeBookmarkUrl(url) {
  const s = String(url || '').trim();
  if (!s) return null;
  if (s.startsWith('javascript:') || s.startsWith('data:') || s.startsWith('file:')) {
    return null;
  }
  if (!/^https?:\/\//i.test(s)) return null;
  return s;
}

// normalizeBookmarkTitle 截断过长标题，防止 UI 被撑爆。
function normalizeBookmarkTitle(title, maxLen) {
  const t = String(title || '').trim();
  const n = Number(maxLen || 200);
  if (t.length <= n) return t;
  return t.slice(0, n - 1) + '…';
}

module.exports = {
  dedupeBookmarks,
  sanitizeBookmarkUrl,
  normalizeBookmarkTitle,
  flattenFolderTree,
};

// flattenFolderTree 把浏览器书签导出里的 { children:[...] } 树拍平成
// 一维数组，自动带上从根到叶的 folder 路径，方便跟现有书签做差。
function flattenFolderTree(node, prefix) {
  const out = [];
  const cur = Array.isArray(node) ? node : [node];
  const base = Array.isArray(prefix) ? prefix : [];
  for (const n of cur) {
    if (!n || typeof n !== 'object') continue;
    if (Array.isArray(n.children) && n.children.length > 0) {
      const nextFolder = n.title ? base.concat(String(n.title)) : base;
      out.push(...flattenFolderTree(n.children, nextFolder));
      continue;
    }
    if (n.url) {
      out.push({
        title: n.title || '',
        url: n.url,
        folder: base.join('/'),
      });
    }
  }
  return out;
}
