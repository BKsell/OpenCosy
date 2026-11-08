'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./pathcontainmentguard');

const BASE = '/home/user/Downloads/cosy';

test('普通子路径通过', () => {
  const r = guard.applyPathContainmentGuard(BASE, 'exports/report.csv');
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.resolved, BASE + '/exports/report.csv');
});

test('根目录自身通过', () => {
  const r = guard.inspectPath(BASE, '.');
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.resolved, BASE);
});

test('上级目录片段被拒', () => {
  const r = guard.inspectPath(BASE, '../secrets.txt');
  assert.strictEqual(r.reason, guard.REASON.TRAVERSAL);
});

test('绝对路径被拒', () => {
  const r = guard.inspectPath(BASE, '/etc/passwd');
  assert.strictEqual(r.reason, guard.REASON.ABSOLUTE);
});

test('盘符路径被拒', () => {
  const r = guard.inspectPath(BASE, 'C:\\Windows\\System32');
  assert.strictEqual(r.reason, guard.REASON.ABSOLUTE);
});

test('UNC 路径被拒', () => {
  const r = guard.inspectPath(BASE, '\\\\server\\share\\file');
  assert.strictEqual(r.reason, guard.REASON.UNC);
});

test('编码后的上级目录被拒', () => {
  const r = guard.inspectPath(BASE, 'a/%2e%2e/b');
  assert.strictEqual(r.reason, guard.REASON.ENCODED_TRAVERSAL);
});

test('空字节被拒', () => {
  const r = guard.inspectPath(BASE, 'ok\u0000.txt');
  assert.strictEqual(r.reason, guard.REASON.CONTROL);
});

test('空路径被拒', () => {
  const r = guard.inspectPath(BASE, '   ');
  assert.strictEqual(r.reason, guard.REASON.EMPTY);
});

test('超长路径被拒', () => {
  const r = guard.inspectPath(BASE, 'a'.repeat(guard.MAX_PATH_LENGTH + 1));
  assert.strictEqual(r.reason, guard.REASON.TOO_LONG);
});

test('描述文本覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
