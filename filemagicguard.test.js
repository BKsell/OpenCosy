'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./filemagicguard');

function png() {
  return Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0]);
}

function pe() {
  return Buffer.from('MZ\x90\x00\x03\x00\x00\x00', 'binary');
}

test('PNG 声明为 PNG 通过', () => {
  const r = guard.applyFileMagicGuard(png(), 'image/png');
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.kind, guard.KIND.PNG);
});

test('PE 伪装成 PNG 被拒', () => {
  const r = guard.applyFileMagicGuard(pe(), 'image/png');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.EXECUTABLE_MISMATCH);
  assert.strictEqual(r.executable, true);
});

test('ELF 被识别为可执行文件', () => {
  const r = guard.inspectMagic(Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]));
  assert.strictEqual(r.kind, guard.KIND.ELF);
  assert.strictEqual(r.executable, true);
});

test('Java class 被识别为可执行文件', () => {
  const r = guard.inspectMagic(Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52]));
  assert.strictEqual(r.kind, guard.KIND.JAVA);
  assert.strictEqual(r.executable, true);
});

test('PDF 声明为 PDF 通过', () => {
  const r = guard.applyFileMagicGuard(Buffer.from('%PDF-1.7\n'), 'application/pdf');
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.kind, guard.KIND.PDF);
});

test('JPEG 声明为 PDF 被判类型不符', () => {
  const r = guard.applyFileMagicGuard(Buffer.from([0xff, 0xd8, 0xff, 0xe0]), 'application/pdf');
  assert.strictEqual(r.reason, guard.REASON.TYPE_MISMATCH);
});

test('脚本内容被识别为可执行', () => {
  const r = guard.applyFileMagicGuard(Buffer.from('#!/bin/sh\nrm -rf /'), 'text/plain');
  assert.strictEqual(r.kind, guard.KIND.SCRIPT);
  assert.strictEqual(r.executable, true);
});

test('空内容被拒', () => {
  const r = guard.inspectMagic(Buffer.alloc(0));
  assert.strictEqual(r.reason, guard.REASON.EMPTY);
});

test('过短内容被拒', () => {
  const r = guard.inspectMagic(Buffer.from([0x01]));
  assert.strictEqual(r.reason, guard.REASON.TOO_SHORT);
});

test('未知类型被拒', () => {
  const r = guard.applyFileMagicGuard(Buffer.from('random bytes here'));
  assert.strictEqual(r.reason, guard.REASON.UNKNOWN);
});

test('非 Buffer 输入被拒', () => {
  const r = guard.inspectMagic('not a buffer');
  assert.strictEqual(r.reason, guard.REASON.EMPTY);
});

test('描述文本覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
