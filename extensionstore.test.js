'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const os = require('os');
const extStore = require('./extensionstore');

test('sanitizeNameToken keeps alnum and replaces the rest', () => {
  assert.strictEqual(extStore.sanitizeNameToken('CoolExt'), 'CoolExt');
  assert.strictEqual(extStore.sanitizeNameToken('a.b/c'), 'a_b_c');
  assert.strictEqual(extStore.sanitizeNameToken('..\\'), '___');
  assert.strictEqual(extStore.sanitizeNameToken(null), '');
});

test('sanitizeVersionToken allows dot underscore hyphen', () => {
  assert.strictEqual(extStore.sanitizeVersionToken('1.2.3-beta_4'), '1.2.3-beta_4');
  assert.strictEqual(extStore.sanitizeVersionToken('v1/../2'), 'v1_.._2');
});

test('buildExtensionId produces safe id or null', () => {
  assert.strictEqual(extStore.buildExtensionId('MyExt', '1.0.0'), 'MyExt_1.0.0');
  assert.strictEqual(extStore.buildExtensionId('a/b', '1'), 'a_b_1');
  // name 全是符号 -> 消毒后无字母数字 -> null
  assert.strictEqual(extStore.buildExtensionId('...', '1.0'), null);
  // version 无任何字母数字 -> null
  assert.strictEqual(extStore.buildExtensionId('Name', '...'), null);
  assert.strictEqual(extStore.buildExtensionId(undefined, '1'), null);
});

test('buildExtensionId rejects overlong ids', () => {
  const longName = 'a'.repeat(extStore.MAX_ID_LENGTH);
  assert.strictEqual(extStore.buildExtensionId(longName, '1'), null);
});

test('isSafeEntryName rejects traversal, separators, control chars and overlong names', () => {
  const good = ['manifest.json', 'bg.js', 'icons', 'a-b_c.png', '中文字体.ttf'];
  for (const n of good) assert.ok(extStore.isSafeEntryName(n), `expected safe: ${n}`);
  const bad = ['', '.', '..', 'a/b', 'a\\b', '/abs', 'C:x', 'evil.exe:stream', 'a*b', 'a?b', 'a|b', 'a\0b', 'l\nn'];
  for (const n of bad) assert.ok(!extStore.isSafeEntryName(n), `expected unsafe: ${JSON.stringify(n)}`);
  const overlong = 'x'.repeat(extStore.MAX_ENTRY_NAME_BYTES + 1);
  assert.ok(!extStore.isSafeEntryName(overlong));
});

test('resolveWithinRoot stays inside root', () => {
  const root = path.join(os.tmpdir(), 'oc-ext-root');
  assert.strictEqual(extStore.resolveWithinRoot(root, 'abc', 'manifest.json'),
    path.join(root, 'abc', 'manifest.json'));
  // .. 折叠后跑出 root -> null
  assert.strictEqual(extStore.resolveWithinRoot(root, '..', 'evil'), null);
  assert.strictEqual(extStore.resolveWithinRoot(root, 'a', '..', '..', 'evil'), null);
  assert.strictEqual(extStore.resolveWithinRoot('relative/root', 'x'), null);
});

test('resolveExtensionDir accepts single segment and blocks traversal', () => {
  const root = path.join(os.tmpdir(), 'oc-extensions');
  assert.strictEqual(extStore.resolveExtensionDir(root, 'MyExt_1.0.0'),
    path.join(root, 'MyExt_1.0.0'));
  const bad = ['', '.', '..', 'a/b', 'a\\b', '../sibling', 'x'.repeat(extStore.MAX_ID_LENGTH + 1)];
  for (const id of bad) {
    assert.strictEqual(extStore.resolveExtensionDir(root, id), null, `expected null: ${id}`);
  }
});

test('createCopyBudget enforces entry and byte ceilings', () => {
  const budget = extStore.createCopyBudget({ maxEntries: 2, maxBytes: 10, maxDepth: 1 });
  assert.ok(budget.noteEntry());
  assert.ok(budget.noteEntry());
  assert.ok(!budget.noteEntry());
  const b2 = extStore.createCopyBudget({ maxBytes: 10 });
  assert.ok(b2.addBytes(6));
  assert.ok(!b2.addBytes(5));
  const b3 = extStore.createCopyBudget({ maxBytes: 10 });
  assert.ok(b3.addBytes(10));
  assert.ok(!b3.addBytes(1));
});

test('classifyCopyEntry accepts normal file/dir and counts bytes', () => {
  const budget = extStore.createCopyBudget({});
  const fileVerdict = extStore.classifyCopyEntry({ name: 'a.js', symlink: false, directory: false, size: 10 }, 1, budget);
  assert.strictEqual(fileVerdict.action, extStore.COPY_ACCEPT_FILE);
  assert.strictEqual(budget.bytes, 10);
  const dirVerdict = extStore.classifyCopyEntry({ name: 'icons', symlink: false, directory: true }, 1, budget);
  assert.strictEqual(dirVerdict.action, extStore.COPY_ACCEPT_DIR);
});

test('classifyCopyEntry skips symlinks and unsafe names', () => {
  const budget = extStore.createCopyBudget({});
  const linkVerdict = extStore.classifyCopyEntry({ name: 'id_rsa', symlink: true, directory: false, size: 0 }, 1, budget);
  assert.strictEqual(linkVerdict.action, extStore.COPY_SKIP);
  assert.strictEqual(linkVerdict.reason, 'symlink');
  const traversal = extStore.classifyCopyEntry({ name: '..', symlink: false, directory: true }, 1, budget);
  assert.strictEqual(traversal.action, extStore.COPY_SKIP);
  assert.strictEqual(traversal.reason, 'unsafe-name');
  // 跳过不计入预算
  assert.strictEqual(budget.entries, 0);
});

test('classifyCopyEntry rejects on depth/count/byte overflow', () => {
  const depthBudget = extStore.createCopyBudget({ maxDepth: 2 });
  assert.strictEqual(
    extStore.classifyCopyEntry({ name: 'deep', symlink: false, directory: true }, 3, depthBudget).action,
    extStore.COPY_REJECT);
  const byteBudget = extStore.createCopyBudget({ maxBytes: 5 });
  const over = extStore.classifyCopyEntry({ name: 'big.bin', symlink: false, directory: false, size: 6 }, 1, byteBudget);
  assert.strictEqual(over.action, extStore.COPY_REJECT);
  assert.strictEqual(over.reason, 'total-bytes-exceeded');
});
