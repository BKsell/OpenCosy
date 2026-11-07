'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./ifrangeguard');

test('缺头不改动', () => {
  const r = guard.applyIfRangeGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('ETag 合规', () => {
  const headers = { 'if-range': '"v1"' };
  const r = guard.applyIfRangeGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('HTTP 日期合规', () => {
  const headers = { 'if-range': 'Wed, 21 Oct 2026 07:28:00 GMT' };
  const r = guard.applyIfRangeGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('非 GMT 日期删除', () => {
  const headers = { 'if-range': 'Wed, 21 Oct 2026 07:28:00 +0800' };
  const r = guard.applyIfRangeGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['if-range'], undefined);
});

test('列表删除', () => {
  const headers = { 'if-range': '"a", "b"' };
  const r = guard.applyIfRangeGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});

test('多值删除', () => {
  const headers = { 'if-range': ['"a"', '"b"'] };
  const r = guard.applyIfRangeGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
});

test('超长删除', () => {
  const headers = { 'if-range': `"${'x'.repeat(120)}"` };
  const r = guard.applyIfRangeGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_LONG);
});
