'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./archiveentryguard');

test('普通条目通过', () => {
  const r = guard.applyArchiveEntryGuard(['theme.json', 'icons/16.png', 'icons/32.png']);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.count, 3);
});

test('空列表被拒', () => {
  const r = guard.inspectArchive([]);
  assert.strictEqual(r.reason, guard.REASON.EMPTY);
});

test('非列表被拒', () => {
  const r = guard.inspectArchive('theme.json');
  assert.strictEqual(r.reason, guard.REASON.NOT_LIST);
});

test('绝对路径条目被拒', () => {
  const r = guard.inspectEntryName('/etc/passwd');
  assert.strictEqual(r.reason, guard.REASON.ABSOLUTE);
});

test('盘符条目被拒', () => {
  const r = guard.inspectEntryName('C:/Windows/system32/evil.dll');
  assert.strictEqual(r.reason, guard.REASON.DRIVE);
});

test('上级目录条目被拒', () => {
  const r = guard.inspectEntryName('../../.bashrc');
  assert.strictEqual(r.reason, guard.REASON.TRAVERSAL);
});

test('反斜杠条目被拒', () => {
  const r = guard.inspectEntryName('..\\evil.exe');
  assert.strictEqual(r.reason, guard.REASON.BACKSLASH);
});

test('空字节条目被拒', () => {
  const r = guard.inspectEntryName('a\u0000b.txt');
  assert.strictEqual(r.reason, guard.REASON.CONTROL);
});

test('超长条目名被拒', () => {
  const r = guard.inspectEntryName('a'.repeat(guard.MAX_NAME + 1));
  assert.strictEqual(r.reason, guard.REASON.TOO_LONG_NAME);
});

test('重复条目被拒', () => {
  const r = guard.inspectArchive(['a.txt', 'A.TXT']);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
});

test('条目数量过多被拒', () => {
  const entries = new Array(guard.MAX_ENTRIES + 1).fill('a.txt');
  const r = guard.inspectArchive(entries);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY_ENTRIES);
});

test('压缩炸弹比例被拒', () => {
  const r = guard.inspectArchive(['a.bin'], { compressedSize: 10, uncompressedSize: 10 * (guard.MAX_RATIO + 1) });
  assert.strictEqual(r.reason, guard.REASON.BOMB_RATIO);
});

test('描述文本覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
