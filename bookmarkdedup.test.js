'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const d = require('./bookmarkdedup');

test('已有书签去重', () => {
  const existing = [{ title: 'GH', url: 'https://github.com' }];
  const incoming = [
    { title: 'GH', url: 'https://github.com' },
    { title: 'GL', url: 'https://gitcode.com' },
  ];
  const r = d.dedupeBookmarks(incoming, existing);
  assert.equal(r.toAdd.length, 1);
  assert.equal(r.duplicates.length, 1);
  assert.equal(r.toAdd[0].url, 'https://gitcode.com');
});

test('incoming 内部去重', () => {
  const incoming = [
    { title: 'A', url: 'https://a.com' },
    { title: 'A', url: 'https://a.com' },
  ];
  const r = d.dedupeBookmarks(incoming, []);
  assert.equal(r.toAdd.length, 1);
  assert.equal(r.duplicates.length, 1);
});

test('自定义 keyFn', () => {
  const incoming = [
    { title: 'A', url: 'https://a.com', folder: 'x' },
    { title: 'B', url: 'https://a.com', folder: 'y' },
  ];
  const r = d.dedupeBookmarks(incoming, [], (b) => b.url);
  assert.equal(r.toAdd.length, 1);
});

test('sanitizeBookmarkUrl 拒 javascript/data/file', () => {
  assert.equal(d.sanitizeBookmarkUrl('javascript:alert(1)'), null);
  assert.equal(d.sanitizeBookmarkUrl('data:text/html,x'), null);
  assert.equal(d.sanitizeBookmarkUrl('file:///etc/passwd'), null);
  assert.equal(d.sanitizeBookmarkUrl('ftp://x'), null);
  assert.equal(d.sanitizeBookmarkUrl('https://a.com'), 'https://a.com');
});

test('normalizeBookmarkTitle 截断', () => {
  const long = 'x'.repeat(500);
  const out = d.normalizeBookmarkTitle(long, 100);
  assert.equal(out.length, 100);
  assert.ok(out.endsWith('…'));
  assert.equal(d.normalizeBookmarkTitle('short', 100), 'short');
});
