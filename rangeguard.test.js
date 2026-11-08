'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./rangeguard');

function h(value) {
  return { range: [value] };
}

test('缺头不改动', () => {
  const r = guard.applyRangeGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('单区间合规', () => {
  const headers = h('bytes=0-100');
  const r = guard.applyRangeGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('非 bytes 单位被删除', () => {
  const headers = h('items=0-1');
  const r = guard.applyRangeGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_UNIT);
  assert.strictEqual(headers.range, undefined);
});

test('非法区间被剔除', () => {
  const headers = h('bytes=0-10, abc, 20-30');
  const r = guard.applyRangeGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_RANGE);
  assert.strictEqual(headers.range, 'bytes=0-10,20-30');
});

test('区间过多整体删除', () => {
  const headers = h('bytes=0-1,2-3,4-5,6-7');
  const r = guard.applyRangeGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
});

test('倒序区间非法', () => {
  const headers = h('bytes=500-400');
  const r = guard.applyRangeGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_RANGE);
  assert.strictEqual(headers.range, undefined);
});
