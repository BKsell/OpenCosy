'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./headerbudgetguard');

test('常规响应头在预算内', () => {
  const headers = { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' };
  const r = guard.applyHeaderBudgetGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.strictEqual(r.count, 2);
});

test('空对象返回 empty', () => {
  const r = guard.applyHeaderBudgetGuard({});
  assert.strictEqual(r.reason, guard.REASON.EMPTY);
});

test('null 返回 empty', () => {
  const r = guard.applyHeaderBudgetGuard(null);
  assert.strictEqual(r.reason, guard.REASON.EMPTY);
});

test('数量超预算被标记', () => {
  const headers = {};
  for (let i = 0; i < guard.MAX_HEADER_COUNT + 1; i += 1) {
    headers[`x-probe-${i}`] = 'v';
  }
  const r = guard.applyHeaderBudgetGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
});

test('总字节超预算被标记', () => {
  const headers = {};
  for (let i = 0; i < 5; i += 1) {
    headers[`x-chunk-${i}`] = 'y'.repeat(7000);
  }
  const r = guard.applyHeaderBudgetGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_LARGE);
});

test('单值超预算被剥除', () => {
  const headers = { 'x-huge': 'q'.repeat(guard.MAX_VALUE_BYTES + 1), 'x-ok': 'v' };
  const r = guard.applyHeaderBudgetGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERSIZE_VALUE);
  assert.strictEqual(headers['x-huge'], undefined);
  assert.strictEqual(headers['x-ok'], 'v');
});

test('空名称被标记', () => {
  const headers = { '': 'v' };
  const r = guard.applyHeaderBudgetGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.EMPTY_NAME);
});

test('中文取值按字节计数', () => {
  const headers = { 'x-name': '汉字' };
  const r = guard.applyHeaderBudgetGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.strictEqual(r.bytes, 16);
});

test('数组取值计入预算', () => {
  const headers = { 'set-cookie': ['a=1', 'b=2', 'c=3'] };
  const r = guard.applyHeaderBudgetGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.strictEqual(r.count, 1);
});

test('oversizedHeaderKeys 列出超限键', () => {
  const headers = { 'x-huge': 'q'.repeat(guard.MAX_VALUE_BYTES + 1), 'x-ok': 'v' };
  const keys = guard.oversizedHeaderKeys(headers);
  assert.deepStrictEqual(keys, ['x-huge']);
});

test('byteLength 计算多字节', () => {
  assert.strictEqual(guard.byteLength('abc'), 3);
  assert.strictEqual(guard.byteLength('汉'), 3);
  assert.strictEqual(guard.byteLength('😀'), 4);
});

test('describeReason 覆盖分支', () => {
  assert.match(guard.describeReason(guard.REASON.TOO_MANY), /数量/);
  assert.match(guard.describeReason(guard.REASON.TOO_LARGE), /总字节/);
  assert.match(guard.describeReason(guard.REASON.OVERSIZE_VALUE), /剥除/);
  assert.match(guard.describeReason(guard.REASON.EMPTY_NAME), /空名称/);
  assert.match(guard.describeReason(guard.REASON.OK), /预算/);
});
