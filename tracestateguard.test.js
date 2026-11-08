'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./tracestateguard');

test('缺头不改动', () => {
  const r = guard.applyTraceStateGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合法 vendor 条目合规', () => {
  const headers = { tracestate: 'vendor-a=value1, vendor-b=value2' };
  const r = guard.applyTraceStateGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('大写 vendor 名被剔除', () => {
  const headers = { tracestate: 'Vendor=value1, vendor-b=value2' };
  const r = guard.applyTraceStateGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers.tracestate, 'vendor-b=value2');
});

test('缺等号被剔除', () => {
  const headers = { tracestate: 'vendor-a' };
  const r = guard.applyTraceStateGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers.tracestate, undefined);
});

test('重复 vendor 去重', () => {
  const headers = { tracestate: 'vendor-a=1, vendor-a=2' };
  const r = guard.applyTraceStateGuard(headers);
  assert.strictEqual(headers.tracestate, 'vendor-a=1');
});

test('超长整体删除', () => {
  const headers = { tracestate: `vendor-a=${'v'.repeat(600)}` };
  const r = guard.applyTraceStateGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_LONG);
});

test('条目过多截断', () => {
  const entries = Array.from({ length: 40 }, (_, i) => `v${i}=x`);
  const headers = { tracestate: entries.join(', ') };
  const r = guard.applyTraceStateGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
  assert.strictEqual(headers.tracestate.split(',').length, 32);
});
