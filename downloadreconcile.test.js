'use strict';

const test = require('node:test');
const assert = require('node:assert');
const reconcile = require('./downloadreconcile');

function entry(id, overrides = {}) {
  return {
    id,
    url: 'https://example.com/a.bin',
    filename: 'a.bin',
    host: 'example.com',
    savePath: `/downloads/${id}.bin`,
    partPath: '',
    totalBytes: 100,
    receivedBytes: 100,
    state: 'complete',
    startedAt: 1,
    updatedAt: 2,
    ...overrides,
  };
}

test('reconcileEntry marks matching file ok', () => {
  const result = reconcile.reconcileEntry(entry('e1'), {
    exists: () => true,
    sizeOf: () => 100,
  });
  assert.strictEqual(result.verdict, 'ok');
  assert.strictEqual(result.entry.fileCheck, 'ok');
  assert.strictEqual(result.entry.fileBytes, 100);
});

test('reconcileEntry marks missing file', () => {
  const result = reconcile.reconcileEntry(entry('e2'), {
    exists: () => false,
    sizeOf: () => null,
  });
  assert.strictEqual(result.verdict, 'missing');
  assert.deepStrictEqual(result.change, { id: 'e2', from: 'skipped', to: 'missing' });
});

test('reconcileEntry marks size mismatch', () => {
  const result = reconcile.reconcileEntry(entry('e3'), {
    exists: () => true,
    sizeOf: () => 42,
  });
  assert.strictEqual(result.verdict, 'size-mismatch');
  assert.strictEqual(result.entry.fileBytes, 42);
});

test('reconcileEntry skips entries without savePath', () => {
  const result = reconcile.reconcileEntry(entry('e4', { savePath: '' }), {
    exists: () => true,
    sizeOf: () => 100,
  });
  assert.strictEqual(result.verdict, 'skipped');
  assert.strictEqual(result.change, null);
});

test('reconcileEntry tolerates throwing probes', () => {
  const missingProbe = reconcile.reconcileEntry(entry('e5'), {
    exists: () => { throw new Error('boom'); },
    sizeOf: () => 1,
  });
  assert.strictEqual(missingProbe.verdict, 'unreadable');
  const badSize = reconcile.reconcileEntry(entry('e6'), {
    exists: () => true,
    sizeOf: () => { throw new Error('boom'); },
  });
  assert.strictEqual(badSize.verdict, 'unreadable');
});

test('reconcileEntry reports no change when verdict stable', () => {
  const first = { ...entry('e7'), fileCheck: 'ok', fileBytes: 100 };
  const result = reconcile.reconcileEntry(first, { exists: () => true, sizeOf: () => 100 });
  assert.strictEqual(result.change, null);
});

test('reconcileEntries summarizes mixed batch', () => {
  const list = [
    entry('a'),
    entry('b'),
    entry('c'),
    entry('d', { savePath: '' }),
  ];
  const out = reconcile.reconcileEntries(list, {
    exists: (p) => !p.endsWith('/a.bin'),
    sizeOf: (p) => (p.endsWith('/b.bin') ? 90 : 100),
  });
  assert.strictEqual(out.summary.checked, 4);
  assert.strictEqual(out.summary.ok, 1);
  assert.strictEqual(out.summary.missing, 1);
  assert.strictEqual(out.summary.sizeMismatch, 1);
  assert.strictEqual(out.summary.skipped, 1);
  assert.strictEqual(out.changes.length, 3);
  assert.deepStrictEqual(out.entries.map((e) => e.fileCheck), ['missing', 'size-mismatch', 'ok', 'skipped']);
});

test('reconcileEntries respects maxVerify budget', () => {
  const list = [entry('a'), entry('b'), entry('c')];
  const out = reconcile.reconcileEntries(list, {
    exists: () => true,
    sizeOf: () => 100,
    maxVerify: 2,
  });
  assert.strictEqual(out.summary.checked, 2);
  assert.strictEqual(out.summary.ok, 2);
  assert.strictEqual(out.summary.skipped, 1);
  assert.strictEqual(out.entries[2].fileCheck, 'skipped');
});

test('summarizeReconcile and describeVerdict produce text', () => {
  const text = reconcile.summarizeReconcile({ checked: 3, ok: 2, missing: 1, sizeMismatch: 0, unreadable: 0 });
  assert.ok(text.includes('核对 3 条'));
  assert.ok(text.includes('1 条文件缺失'));
  assert.strictEqual(reconcile.describeVerdict('missing'), '记录存在但文件已被移除');
  assert.strictEqual(reconcile.describeVerdict('nope'), '未知核对结果');
});

test('reconcileEntries keeps unreadable entries visible', () => {
  const list = [entry('u1'), entry('u2')];
  const out = reconcile.reconcileEntries(list, {
    exists: (p) => p.endsWith('u1.bin'),
    sizeOf: () => { throw new Error('EACCES'); },
  });
  assert.strictEqual(out.summary.unreadable, 1);
  assert.strictEqual(out.summary.missing, 1);
  assert.strictEqual(out.entries[0].fileCheck, 'unreadable');
});

test('reconcileEntries handles empty and broken input', () => {
  const empty = reconcile.reconcileEntries([], { exists: () => true, sizeOf: () => 0 });
  assert.strictEqual(empty.summary.checked, 0);
  const broken = reconcile.reconcileEntries([null, entry('x')], {
    exists: () => true,
    sizeOf: () => 100,
  });
  assert.strictEqual(broken.entries.length, 2);
  assert.strictEqual(broken.summary.skipped, 1);
  const text = reconcile.summarizeReconcile(null);
  assert.ok(text.includes('未执行'));
});
