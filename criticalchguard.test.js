'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./criticalchguard');

test('缺头不改动', () => {
  const r = guard.applyCriticalChGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合法 token 合规', () => {
  const headers = { 'critical-ch': 'sec-ch-ua, sec-ch-ua-mobile' };
  const r = guard.applyCriticalChGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('大写归一为小写', () => {
  const headers = { 'critical-ch': 'Sec-CH-UA' };
  const r = guard.applyCriticalChGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers['critical-ch'], 'sec-ch-ua');
});

test('非法 token 被剔除', () => {
  const headers = { 'critical-ch': 'sec-ch-ua, bad token' };
  const r = guard.applyCriticalChGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['critical-ch'], 'sec-ch-ua');
});

test('重复项去重', () => {
  const headers = { 'critical-ch': 'sec-ch-ua, sec-ch-ua' };
  const r = guard.applyCriticalChGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
});

test('超长列表截断', () => {
  const tokens = Array.from({ length: 12 }, (_, i) => `sec-ch-h${i}`);
  const headers = { 'critical-ch': tokens.join(', ') };
  const r = guard.applyCriticalChGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
  assert.strictEqual(headers['critical-ch'].split(',').length, 8);
});

test('空值删除', () => {
  const headers = { 'critical-ch': '   ' };
  const r = guard.applyCriticalChGuard(headers);
  assert.strictEqual(headers['critical-ch'], undefined);
});
