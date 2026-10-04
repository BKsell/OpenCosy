'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const bg = require('./bookmarkguard');

const NOW = 1_700_000_000_000;

test('sanitizeBookmarkTitle 归一制表换行回车、删其余控制字符、压空白、截上界', () => {
  assert.equal(bg.sanitizeBookmarkTitle('a\tb\nc\rd'), 'a b c d');
  assert.equal(bg.sanitizeBookmarkTitle('x\u0000y\u001Bz\u007Fw'), 'xyzw');
  assert.equal(bg.sanitizeBookmarkTitle('  多    空格  '), '多 空格');
  assert.equal(bg.sanitizeBookmarkTitle(42), '');
  assert.equal(bg.sanitizeBookmarkTitle(null), '');
  const long = '页'.repeat(bg.MAX_TITLE_CHARS + 80);
  assert.equal(bg.sanitizeBookmarkTitle(long).length, bg.MAX_TITLE_CHARS);
});

test('sanitizeBookmarkUrl 仅接受 http/https、可解析、host 非空、限长', () => {
  assert.equal(bg.sanitizeBookmarkUrl('https://example.com/a').ok, true);
  assert.equal(bg.sanitizeBookmarkUrl('http://a.test:8080/x?y=1').ok, true);
  const blocked = ['file:///C:/secret.txt', 'about:blank', 'cosy://bookmarks',
    'javascript:alert(1)', 'data:text/html,x', 'chrome://version',
    'view-source:https://a.test', '\\\\wsl$\\share', 'not a url', '', null, 123];
  for (const bad of blocked) {
    assert.equal(bg.sanitizeBookmarkUrl(bad).ok, false, String(bad));
  }
  assert.equal(bg.sanitizeBookmarkUrl('file:///C:/x').reason, bg.SKIP_BAD_PROTOCOL);
  assert.equal(bg.sanitizeBookmarkUrl('').reason, bg.SKIP_BAD_URL);
  const tooLong = 'https://e.test/' + 'a'.repeat(bg.MAX_URL_CHARS);
  assert.equal(bg.sanitizeBookmarkUrl(tooLong).reason, bg.SKIP_URL_TOO_LONG);
});

test('sanitizeBookmarkItem 拒绝非对象与坏 url，净化 title 并补 addedDate', () => {
  assert.equal(bg.sanitizeBookmarkItem(null, NOW).ok, false);
  assert.equal(bg.sanitizeBookmarkItem('x', NOW).ok, false);
  assert.equal(bg.sanitizeBookmarkItem([], NOW).ok, false);
  assert.equal(bg.sanitizeBookmarkItem({ url: 'javascript:x' }, NOW).reason, bg.SKIP_BAD_PROTOCOL);

  const r = bg.sanitizeBookmarkItem({ url: 'https://a.test/p', title: 'A\u0007' }, NOW);
  assert.equal(r.ok, true);
  assert.equal(r.item.url, 'https://a.test/p');
  assert.equal(r.item.title, 'A');
  // 缺 addedDate 用 now 补成 ISO。
  assert.equal(r.item.addedDate, new Date(NOW).toISOString());

  // title 为空时用 host 兜底。
  const r2 = bg.sanitizeBookmarkItem({ url: 'https://www.example.com/', title: '  ' }, NOW);
  assert.equal(r2.item.title, 'example.com');

  // 非法 addedDate 也回退到 now。
  const r3 = bg.sanitizeBookmarkItem({ url: 'https://b.test/', addedDate: 'not-a-date' }, NOW);
  assert.equal(r3.item.addedDate, new Date(NOW).toISOString());

  // 合法 addedDate 被规范化（等价时间的 ISO）。
  const r4 = bg.sanitizeBookmarkItem({ url: 'https://c.test/', addedDate: '2020-01-02T03:04:05.000Z' }, NOW);
  assert.equal(r4.item.addedDate, '2020-01-02T03:04:05.000Z');
});

test('sanitizeBookmarkList 非数组收敛为空，逐条丢弃脏项并按 url 去重', () => {
  assert.deepEqual(bg.sanitizeBookmarkList(null, NOW).items, []);
  assert.deepEqual(bg.sanitizeBookmarkList({ url: 'x' }, NOW).items, []);
  assert.deepEqual(bg.sanitizeBookmarkList('nope', NOW).items, []);

  const out = bg.sanitizeBookmarkList([
    null,
    42,
    'str',
    { url: 'file:///x' },
    { url: 'https://a.test/', title: 'A' },
    { url: 'https://a.test/', title: 'A2' },           // 重复 url
    { url: 'https://b.test/', title: 'B\u0000' },      // 标题控制字符被清
  ], NOW);
  assert.equal(out.items.length, 2);
  assert.equal(out.items[0].url, 'https://a.test/');
  assert.equal(out.items[1].url, 'https://b.test/');
  assert.equal(out.items[1].title, 'B');
  assert.equal(out.dropped, 4);
  assert.equal(out.duplicates, 1);
});

test('sanitizeBookmarkList 截断到硬上界，超出计入 dropped', () => {
  const raw = [];
  for (let i = 0; i < bg.MAX_BOOKMARK_ITEMS + 25; i++) {
    raw.push({ url: `https://h${i}.test/`, title: `H${i}` });
  }
  const out = bg.sanitizeBookmarkList(raw, NOW);
  assert.equal(out.items.length, bg.MAX_BOOKMARK_ITEMS);
  assert.equal(out.dropped, 25);
});

test('upsertBookmark 新增 / 去重 / 拒绝三态正确', () => {
  const st = bg.createBookmarkState();
  const a = bg.upsertBookmark(st, { url: 'https://a.test/' }, NOW);
  assert.equal(a.status, 'added');
  const dup = bg.upsertBookmark(st, { url: 'https://a.test/', title: 'X' }, NOW);
  assert.equal(dup.status, 'duplicate');
  assert.equal(st.items.length, 1);
  const rej = bg.upsertBookmark(st, { url: 'about:blank' }, NOW);
  assert.equal(rej.status, 'rejected');
  assert.equal(st.items.length, 1);
});

test('mergeImportedBookmarks 跳过脏项与重复，返回 added/skipped 并裁上界', () => {
  const st = bg.createBookmarkState([{ url: 'https://old.test/', title: 'O', addedDate: new Date(NOW).toISOString() }]);
  const res = bg.mergeImportedBookmarks(st, [
    { url: 'https://old.test/' },          // 已存在
    { url: 'https://new.test/' },          // 新增
    { url: 'file:///etc/passwd' },         // 非法
    null,
    { url: 'https://new2.test/' },         // 新增
  ], NOW);
  assert.equal(res.added, 2);
  assert.equal(res.skipped, 3);
  assert.equal(st.items.length, 3);
});

test('removeBookmark / clearAllBookmarks 行为正确', () => {
  const st = bg.createBookmarkState();
  bg.upsertBookmark(st, { url: 'https://a.test/' }, NOW);
  bg.upsertBookmark(st, { url: 'https://b.test/' }, NOW);
  assert.equal(bg.removeBookmark(st, 'https://a.test/'), true);
  assert.equal(bg.removeBookmark(st, 'https://a.test/'), false);
  assert.equal(st.items.length, 1);
  assert.equal(bg.clearAllBookmarks(st), 1);
  assert.equal(st.items.length, 0);
  assert.equal(bg.clearAllBookmarks(null), 0);
});
