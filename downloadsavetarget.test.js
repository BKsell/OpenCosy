'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const target = require('./downloadsavetarget');

const ROOT = path.join(path.sep, 'home', 'tester', 'Downloads');

test('accepts a normal nested target', () => {
  const file = path.join(ROOT, 'sub', 'report.pdf');
  const res = target.auditSaveTarget(ROOT, file, 'report.pdf');
  assert.strictEqual(res.ok, true);
  assert.strictEqual(res.reason, target.REASON.OK);
  assert.strictEqual(res.name, 'report.pdf');
});

test('accepts target directly inside root', () => {
  const file = path.join(ROOT, 'a.bin');
  const res = target.auditSaveTarget(ROOT, file, 'a.bin');
  assert.strictEqual(res.ok, true);
});

test('rejects missing root and target', () => {
  assert.strictEqual(target.auditSaveTarget('', path.join(ROOT, 'a'), 'a').reason, target.REASON.EMPTY_ROOT);
  assert.strictEqual(target.auditSaveTarget(ROOT, '', 'a').reason, target.REASON.EMPTY_TARGET);
});

test('rejects relative and non clean paths', () => {
  assert.strictEqual(target.auditSaveTarget(ROOT, 'downloads/a.bin', 'a.bin').reason, target.REASON.BAD_PATH);
  const withNul = `${path.join(ROOT, 'a.bin')}\u0000`;
  assert.strictEqual(target.auditSaveTarget(ROOT, withNul, 'a.bin').reason, target.REASON.BAD_PATH);
});

test('rejects escape outside the root', () => {
  const outside = path.join(path.sep, 'tmp', 'evil.bin');
  const res = target.auditSaveTarget(ROOT, outside, 'evil.bin');
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.reason, target.REASON.OUTSIDE_ROOT);
});

test('rejects escaping the root through dot segments', () => {
  const escaped = path.join(ROOT, '..', 'evil.bin');
  const res = target.auditSaveTarget(ROOT, escaped, 'evil.bin');
  assert.strictEqual(res.reason, target.REASON.OUTSIDE_ROOT);
});

test('rejects root itself as a target', () => {
  const res = target.auditSaveTarget(ROOT, ROOT, 'Downloads');
  assert.strictEqual(res.reason, target.REASON.OUTSIDE_ROOT);
});

test('rejects names not matching the target basename', () => {
  const res = target.auditSaveTarget(ROOT, path.join(ROOT, 'real.bin'), 'other.bin');
  assert.strictEqual(res.reason, target.REASON.BAD_PATH);
});

test('auditSaveName rejects unsafe shapes', () => {
  const cases = [
    ['', target.REASON.BAD_NAME],
    ['.', target.REASON.BAD_NAME],
    ['..', target.REASON.BAD_NAME],
    ['a/b', target.REASON.BAD_NAME],
    ['a\\b', target.REASON.BAD_NAME],
    ['a.bin.', target.REASON.BAD_NAME],
    ['a.bin ', target.REASON.BAD_NAME],
    ['a.bin:ads', target.REASON.BAD_NAME],
    ['a\u0001.bin', target.REASON.BAD_NAME],
    ['con', target.REASON.RESERVED_NAME],
    ['CON.txt', target.REASON.RESERVED_NAME],
    ['lpt9.log', target.REASON.RESERVED_NAME],
    ['x'.repeat(target.MAX_SAVE_NAME_CHARS + 1), target.REASON.BAD_NAME],
  ];
  for (const [name, reason] of cases) {
    assert.strictEqual(target.auditSaveName(name), reason, `name=${JSON.stringify(name)}`);
  }
});

test('auditSaveName accepts ordinary names', () => {
  for (const name of ['a.bin', '报告 final.pdf', 'archive.tar.gz', 'file (1).zip', '.gitignore']) {
    assert.strictEqual(target.auditSaveName(name), target.REASON.OK, `name=${name}`);
  }
});

test('alternate data stream detection skips drive colon', () => {
  assert.strictEqual(target.hasAlternateDataStream('C:\\Downloads\\a.bin'), false);
  assert.strictEqual(target.hasAlternateDataStream('C:\\Downloads\\a.bin:evil'), true);
  assert.strictEqual(target.hasAlternateDataStream('/home/a.bin:evil'), true);
});

test('descriptions are unique and non empty', () => {
  const reasons = Object.values(target.REASON);
  const seen = new Set();
  for (const reason of reasons) {
    const msg = target.describeSaveTargetReject(reason);
    assert.ok(msg.length > 0);
    assert.ok(!seen.has(msg), `duplicate message ${reason}`);
    seen.add(msg);
  }
  assert.ok(target.describeSaveTargetReject('nope').length > 0);
});
