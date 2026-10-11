// downloadshelf.test.js —— 下载栏快照净化内核的测试。

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const shelf = require('./downloadshelf');

test('stripControlChars removes C0 and ANSI sequences', () => {
  assert.strictEqual(shelf.stripControlChars('a\x00b\x1b[31mc\x1b]0;title\x07d'), 'abcd');
  assert.strictEqual(shelf.stripControlChars('plain'), 'plain');
  assert.strictEqual(shelf.stripControlChars(''), '');
  assert.strictEqual(shelf.stripControlChars(123), '');
});

test('truncateRunes bounds by rune count', () => {
  assert.strictEqual(shelf.truncateRunes('中文abc', 4), '中文ab');
  assert.strictEqual(shelf.truncateRunes('abc', 10), 'abc');
  assert.strictEqual(shelf.truncateRunes(null, 3), '');
});

test('clampNumber clamps and defaults', () => {
  assert.strictEqual(shelf.clampNumber(150, 0, 100), 100);
  assert.strictEqual(shelf.clampNumber(-5, 0, 100), 0);
  assert.strictEqual(shelf.clampNumber(42, 0, 100), 42);
  assert.strictEqual(shelf.clampNumber(NaN, 0, 100), 0);
  assert.strictEqual(shelf.clampNumber(Infinity, 0, 100), 0);
});

test('sanitizeShelfEntry cleans hostile fields', () => {
  const raw = {
    id: 1,
    filename: 'evil\x1b[31mfile\x00.jar',
    url: 'https://example.com/a\x00b?q=\x1b]0;x\x07<script>',
    progress: 999,
    speed: '1 MB/s\x00',
    status: 'interrupted',
    savePath: 'C:\\secret\\full\\path.exe',
    errorMessage: 'boom\x1b[2J',
    startTime: 'abc',
  };
  const e = shelf.sanitizeShelfEntry(raw, shelf.ShelfLimits);
  assert.strictEqual(e.filename, 'evilfile.jar');
  assert.strictEqual(e.progress, 100);
  assert.ok(!e.url.includes('\x00'));
  assert.ok(!e.url.includes('\x1b'));
  assert.strictEqual(e.status, 'interrupted');
  assert.strictEqual(e.hasSavePath, true);
  assert.ok(!('savePath' in e));
  assert.strictEqual(e.startTime, null);
  assert.strictEqual(e.errorMessage, 'boom');
});

test('unknown status downgrades to pending', () => {
  const e = shelf.sanitizeShelfEntry({ status: 'weird-status' }, shelf.ShelfLimits);
  assert.strictEqual(e.status, 'pending');
});

test('buildShelfSnapshot keeps latest maxItems in order', () => {
  const downloads = [];
  for (let i = 0; i < 8; i++) {
    downloads.push({ id: String(i), filename: 'f' + i + '.jar', status: 'completed', progress: 100 });
  }
  const snap = shelf.buildShelfSnapshot(downloads, shelf.ShelfLimits);
  assert.strictEqual(snap.items.length, 3);
  assert.strictEqual(snap.items[0].id, '7');
  assert.strictEqual(snap.items[2].id, '5');
  assert.strictEqual(snap.stats.total, 8);
  assert.strictEqual(snap.stats.completed, 8);
});

test('shelfStats counts by status', () => {
  const downloads = [
    { status: 'progress' },
    { status: 'pending' },
    { status: 'completed' },
    { status: 'interrupted' },
    { status: 'cancelled' },
    { status: 'bogus' },
  ];
  const s = shelf.shelfStats(downloads);
  assert.deepStrictEqual(s, { total: 6, active: 2, completed: 1, failed: 1, cancelled: 1 });
});

test('sanitizeDownloadRecord keeps savePath when explicitly provided', () => {
  const r = shelf.sanitizeDownloadRecord(
    { filename: 'a\x00.jar', status: 'completed', savePath: 'C:\\x\\y.jar' },
    shelf.ShelfLimits,
  );
  assert.strictEqual(r.filename, 'a.jar');
  assert.strictEqual(r.savePath, 'C:\\x\\y.jar');
});

test('summarizeShelf renders one line', () => {
  const s = shelf.summarizeShelf(shelf.shelfStats([{ status: 'progress' }, { status: 'completed' }]));
  assert.match(s, /^download-shelf total=2 active=1 completed=1 failed=0 cancelled=0$/);
});
