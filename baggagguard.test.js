'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./baggagguard');

test('缺头不改动', () => {
  const r = guard.applyBaggageGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合法 baggage 合规', () => {
  const headers = { baggage: 'user-id=42; prop=value, trace=abc' };
  const r = guard.applyBaggageGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('控制字符直接删除', () => {
  const headers = { baggage: 'user-id=4\u00002' };
  const r = guard.applyBaggageGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers.baggage, undefined);
});

test('非法成员被剔除', () => {
  const headers = { baggage: 'user-id=42, bad member=%' };
  const r = guard.applyBaggageGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers.baggage, 'user-id=42');
});

test('重复键去重', () => {
  const headers = { baggage: 'user-id=1, user-id=2' };
  const r = guard.applyBaggageGuard(headers);
  assert.strictEqual(headers.baggage, 'user-id=1');
});

test('超长整体删除', () => {
  const headers = { baggage: `user-id=${'v'.repeat(4200)}` };
  const r = guard.applyBaggageGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_LONG);
});

test('成员过多截断', () => {
  const members = Array.from({ length: 20 }, (_, i) => `k${i}=v`);
  const headers = { baggage: members.join(', ') };
  const r = guard.applyBaggageGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
  assert.strictEqual(headers.baggage.split(',').length, 16);
});
