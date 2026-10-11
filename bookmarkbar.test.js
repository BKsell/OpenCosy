'use strict';

const test = require('node:test');
const assert = require('node:assert');

const {
  MAX_BAR_ITEMS,
  isBarSafeUrl,
  cleanBarTitle,
  buildBookmarkBarItems,
  classifyBookmarkClick,
  bookmarkBarOverflow,
  bookmarkBarVisible,
} = require('./bookmarkbar');

test('isBarSafeUrl 只收 http/https 且拒绝危险 scheme', () => {
  assert.equal(isBarSafeUrl('https://example.com'), true);
  assert.equal(isBarSafeUrl('http://example.com/path?q=1'), true);
  assert.equal(isBarSafeUrl('javascript:alert(1)'), false);
  assert.equal(isBarSafeUrl('data:text/html,<script>'), false);
  assert.equal(isBarSafeUrl('file:///etc/passwd'), false);
  assert.equal(isBarSafeUrl('cosy://history'), false);
  assert.equal(isBarSafeUrl('https://'), false); // 无主机名
  assert.equal(isBarSafeUrl(''), false);
  assert.equal(isBarSafeUrl(42), false);
  assert.equal(isBarSafeUrl('https://a.com/' + 'x'.repeat(3000)), false); // 超长
});

test('cleanBarTitle 剥控制字符并限长保头尾', () => {
  assert.equal(cleanBarTitle('  正常标题  '), '正常标题');
  assert.equal(cleanBarTitle('a\u0000b\u0007c'), 'abc');
  // 40 上限：保头 19 + 省略号 + 保尾 19 = 39。
  assert.equal(cleanBarTitle('x'.repeat(100)).length, 39);
  const long = cleanBarTitle('头部'.padEnd(60, '尾'));
  assert.ok(long.length <= 40);
  assert.ok(long.includes('…'));
  assert.equal(cleanBarTitle(null), '');
  assert.equal(cleanBarTitle(undefined), '');
});

test('buildBookmarkBarItems 净化、去重、上限、溢出计数', () => {
  const mk = (url, title) => ({ url, title, addedDate: '2026-01-01' });
  const input = [
    mk('https://a.com', 'A'),
    mk('HTTPS://A.COM', 'A重复'), // 大小写去重
    mk('javascript:alert(1)', '危险'),
    null,
    mk('https://b.com', 'B\u0000控制'),
    ...Array.from({ length: 30 }, (_, i) => mk(`https://c${i}.com`, `C${i}`)),
  ];
  const { items, overflowCount } = buildBookmarkBarItems(input);
  assert.equal(items.length, MAX_BAR_ITEMS);
  assert.equal(overflowCount, 20); // 32 个安全项 - 12 上限 = 20 溢出
  assert.ok(items.every(it => isBarSafeUrl(it.url)));
  assert.ok(items.every(it => !it.title.includes('\u0000')));
  const keys = new Set(items.map(it => it.key));
  assert.equal(keys.size, items.length, '主键不重复');
  assert.equal(items[0].url, 'https://a.com');
  // 非数组输入
  assert.deepEqual(buildBookmarkBarItems(null), { items: [], overflowCount: 0 });
});

test('classifyBookmarkClick 键位/修饰键归类', () => {
  assert.equal(classifyBookmarkClick({ button: 0 }), 'current');
  assert.equal(classifyBookmarkClick({ button: 0, ctrlKey: true }), 'new-tab');
  assert.equal(classifyBookmarkClick({ button: 0, metaKey: true }), 'new-tab');
  assert.equal(classifyBookmarkClick({ button: 0, ctrlKey: true, shiftKey: true }), 'new-bg-tab');
  assert.equal(classifyBookmarkClick({ button: 0, metaKey: true, shiftKey: true }), 'new-bg-tab');
  assert.equal(classifyBookmarkClick({ button: 1 }), 'new-tab');
  assert.equal(classifyBookmarkClick({ button: 1, shiftKey: true }), 'new-bg-tab');
  assert.equal(classifyBookmarkClick({ button: 2 }), 'ignore');
  assert.equal(classifyBookmarkClick({ button: 0, altKey: true }), 'ignore');
  assert.equal(classifyBookmarkClick(null), 'ignore');
});

test('bookmarkBarOverflow / bookmarkBarVisible', () => {
  const many = Array.from({ length: 20 }, (_, i) => ({ url: `https://x${i}.com`, title: `X${i}` }));
  assert.equal(bookmarkBarOverflow(many), true);
  assert.equal(bookmarkBarOverflow([{ url: 'https://a.com', title: 'A' }]), false);
  assert.equal(bookmarkBarVisible(false, undefined), true); // 取反
  assert.equal(bookmarkBarVisible(true, undefined), false);
  assert.equal(bookmarkBarVisible(true, true), true);      // 显式指定
  assert.equal(bookmarkBarVisible(false, false), false);
});
