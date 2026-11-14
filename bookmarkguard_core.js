'use strict';
const { stripControlChars, collapseSpaces } = require('./modutil_core');

const { MAX_BOOKMARK_ITEMS, SKIP_NOT_OBJECT, constants, isValidISOTimestamp, sanitizeBookmarkItem, sanitizeBookmarkTitle, sanitizeBookmarkUrl } = require('./bookmarkguard_check_core');
function createBookmarkState(initialItems) {
  const items = Array.isArray(initialItems) ? initialItems.slice(0, MAX_BOOKMARK_ITEMS) : [];
  return { items };
}

// findBookmarkIndex 在状态中按 url 查找下标，找不到返回 -1。
function findBookmarkIndex(state, url) {
  if (!state || !Array.isArray(state.items)) return -1;
  for (let i = 0; i < state.items.length; i++) {
    if (state.items[i] && state.items[i].url === url) return i;
  }
  return -1;
}

// capBookmarkItems 把书签裁剪到硬上界（丢弃数组尾部最旧 / 最末项），返回丢弃数。
function capBookmarkItems(state) {
  if (!state || !Array.isArray(state.items)) return 0;
  if (state.items.length <= MAX_BOOKMARK_ITEMS) return 0;
  const dropped = state.items.length - MAX_BOOKMARK_ITEMS;
  state.items.length = MAX_BOOKMARK_ITEMS;
  return dropped;
}

// sanitizeBookmarkList 读盘 / 导入的总入口：把任意 JSON 值收敛成干净书签数组。
//   - 非数组（对象 / null / 数字 / 字符串）一律视为空，避免脏 JSON 进 UI；
//   - 逐条 sanitizeBookmarkItem，非法条目丢弃并计数；
//   - 按 url 去重（保留先出现者）；
//   - 截断到 MAX_BOOKMARK_ITEMS。
// 返回 {items,dropped,duplicates}。
function sanitizeBookmarkList(rawList, now) {
  const items = [];
  let dropped = 0;
  let duplicates = 0;
  if (Array.isArray(rawList)) {
    for (const raw of rawList) {
      const r = sanitizeBookmarkItem(raw, now);
      if (!r.ok) {
        dropped += 1;
        continue;
      }
      if (findBookmarkIndex({ items }, r.item.url) !== -1) {
        duplicates += 1;
        continue;
      }
      if (items.length >= MAX_BOOKMARK_ITEMS) {
        // 已达硬上界：后续合法项也无法容纳，计入丢弃，保证 dropped 精确。
        dropped += 1;
        continue;
      }
      items.push(r.item);
    }
  }
  return { items, dropped, duplicates };
}

// upsertBookmark 新增单条书签；若同 url 已存在则不重复添加（保留原条目）。
// 返回 {status,item}：status 为 'added' | 'duplicate' | 'rejected'。
function upsertBookmark(state, input, now) {
  if (!state || !Array.isArray(state.items)) {
    return { status: 'rejected', item: null, reason: SKIP_NOT_OBJECT };
  }
  const r = sanitizeBookmarkItem(input, now);
  if (!r.ok) return { status: 'rejected', item: null, reason: r.reason };
  if (findBookmarkIndex(state, r.item.url) !== -1) {
    return { status: 'duplicate', item: r.item, reason: '' };
  }
  state.items.push(r.item);
  capBookmarkItems(state);
  return { status: 'added', item: r.item, reason: '' };
}

// mergeImportedBookmarks 把一批外部（HTML 导入 / 同步）书签合并进现有状态：
// 逐条净化、同 url 跳过，最后裁剪上界。返回 {added,skipped}。
function mergeImportedBookmarks(state, incoming, now) {
  if (!state || !Array.isArray(state.items)) return { added: 0, skipped: 0 };
  let added = 0;
  let skipped = 0;
  const list = Array.isArray(incoming) ? incoming : [];
  for (const raw of list) {
    const r = sanitizeBookmarkItem(raw, now);
    if (!r.ok) {
      skipped += 1;
      continue;
    }
    if (findBookmarkIndex(state, r.item.url) !== -1) {
      skipped += 1;
      continue;
    }
    state.items.push(r.item);
    added += 1;
  }
  const dropped = capBookmarkItems(state);
  skipped += dropped;
  return { added, skipped };
}

// removeBookmark 按 url 删除书签，返回是否删除了条目。
function removeBookmark(state, url) {
  if (!state || !Array.isArray(state.items)) return false;
  const idx = findBookmarkIndex(state, url);
  if (idx === -1) return false;
  state.items.splice(idx, 1);
  return true;
}

// clearAllBookmarks 清空全部书签，返回被清除条数。
function clearAllBookmarks(state) {
  if (!state || !Array.isArray(state.items)) return 0;
  const n = state.items.length;
  state.items = [];
  return n;
}

module.exports = Object.freeze(Object.assign({
  stripControlChars,
  collapseSpaces,
  sanitizeBookmarkTitle,
  sanitizeBookmarkUrl,
  isValidISOTimestamp,
  sanitizeBookmarkItem,
  createBookmarkState,
  findBookmarkIndex,
  capBookmarkItems,
  sanitizeBookmarkList,
  upsertBookmark,
  mergeImportedBookmarks,
  removeBookmark,
  clearAllBookmarks,
}, constants));
