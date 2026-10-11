'use strict';

// bookmarkbar.js —— 顶栏书签栏（bookmarks bar）纯逻辑内核。
//
// 与既有“书签管理面板”（showBookmarksBar 浮动面板）互补：书签栏是浏览器式
// 常驻顶栏，一条一个书签、点击即导航。本内核只做纯函数，不碰 DOM / Electron，
// 便于 node:test 覆盖：
//   - buildBookmarkBarItems：把书签列表裁剪成栏上条目（净化、限长、去重、上限）；
//   - bookmarkBarTitle：单条标题截断（保留首尾，中间省略号）；
//   - classifyBookmarkClick：按鼠标键位/修饰键决定“当前标签导航 / 新标签打开 /
//     后台标签打开”，杜绝把 Ctrl 点击误判成普通导航；
//   - bookmarkBarOverflow：当条目数超上限时给出“溢出折叠”标记。
//
// 安全边界（与 bookmarkguard 同一原则）：栏上只渲染 http/https 书签，
// javascript:/data:/file: 一律不显示；title 剥控制字符并限长，防止恶意书签
// 标题注入栏位 DOM。

const MAX_BAR_ITEMS = 12;      // 栏上同时显示上限（超出折叠到「更多」）
const MAX_TITLE_CHARS = 40;    // 单条标题显示上限
const MAX_URL_CHARS = 2048;    // URL 超长丢弃（防止恶意长 URL 撑爆栏位）

// isBarSafeUrl 书签栏只接受 http/https 且带主机名的 URL。
function isBarSafeUrl(url) {
  if (typeof url !== 'string' || url.length === 0 || url.length > MAX_URL_CHARS) return false;
  try {
    const u = new URL(url);
    return (u.protocol === 'http:' || u.protocol === 'https:') && Boolean(u.hostname);
  } catch {
    return false;
  }
}

// cleanBarTitle 去掉控制字符并截断（保头尾，中间省略）。
function cleanBarTitle(title) {
  if (typeof title !== 'string') return '';
  const t = title.replace(/[\u0000-\u001f\u007f]/g, '').trim();
  if (t.length <= MAX_TITLE_CHARS) return t;
  const half = Math.floor((MAX_TITLE_CHARS - 1) / 2);
  return t.slice(0, half) + '…' + t.slice(t.length - half);
}

// buildBookmarkBarItems 从完整书签列表生成栏上条目：
//   [{ url, title, key }]，key 为稳定主键（url 小写），去重、净化、按原顺序，
//   最多 MAX_BAR_ITEMS 条；返回 { items, overflowCount }。
function buildBookmarkBarItems(bookmarks) {
  if (!Array.isArray(bookmarks)) return { items: [], overflowCount: 0 };
  const seen = new Set();
  const items = [];
  let overflowCount = 0;
  for (const raw of bookmarks) {
    if (items.length >= MAX_BAR_ITEMS) { overflowCount++; continue; }
    if (!raw || typeof raw !== 'object') continue;
    const url = typeof raw.url === 'string' ? raw.url : '';
    if (!isBarSafeUrl(url)) continue;
    const key = url.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    items.push({
      url,
      key,
      title: cleanBarTitle(raw.title) || url,
    });
  }
  return { items, overflowCount };
}

// classifyBookmarkClick 把点击事件归类成导航意图：
//   - 'current'   左键或中键/修饰键未指定 → 当前标签导航
//   - 'new-tab'   Ctrl / Cmd + 左键，或中键 → 前台新标签
//   - 'new-bg-tab' Ctrl+Shift / Cmd+Shift + 左键 → 后台新标签
//   - 'ignore'    其它（如右键）→ 由调用方另行处理
function classifyBookmarkClick(evt) {
  if (!evt || typeof evt !== 'object') return 'ignore';
  const { button, ctrlKey, metaKey, shiftKey, altKey } = evt;
  if (button === 2) return 'ignore';
  if (button === 1) {
    // 中键：Shift 修饰进后台，否则前台。
    return shiftKey ? 'new-bg-tab' : 'new-tab';
  }
  if (button !== 0) return 'ignore';
  const mod = Boolean(ctrlKey) || Boolean(metaKey);
  if (altKey) return 'ignore';
  if (mod && shiftKey) return 'new-bg-tab';
  if (mod) return 'new-tab';
  return 'current';
}

// bookmarkBarOverflow 判断是否需要显示「更多」折叠按钮。
function bookmarkBarOverflow(totalBookmarks) {
  return buildBookmarkBarItems(totalBookmarks).overflowCount > 0;
}

// bookmarkBarVisible 切换语义：visible 为 undefined 时取反，否则取给定值。
function bookmarkBarVisible(current, visible) {
  if (typeof visible === 'boolean') return visible;
  return !current;
}

// UMD 式双导出：Node（node:test）走 module.exports，浏览器（index.html 的
// <script src="bookmarkbar.js">）挂 window.BookmarkBar，renderer 无 require 也可用。
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    MAX_BAR_ITEMS,
    MAX_TITLE_CHARS,
    MAX_URL_CHARS,
    isBarSafeUrl,
    cleanBarTitle,
    buildBookmarkBarItems,
    classifyBookmarkClick,
    bookmarkBarOverflow,
    bookmarkBarVisible,
  };
}
if (typeof window !== 'undefined') {
  window.BookmarkBar = {
    MAX_BAR_ITEMS,
    MAX_TITLE_CHARS,
    MAX_URL_CHARS,
    isBarSafeUrl,
    cleanBarTitle,
    buildBookmarkBarItems,
    classifyBookmarkClick,
    bookmarkBarOverflow,
    bookmarkBarVisible,
  };
}
