'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./coopguard');

test('缺头不改动', () => {
  const r = guard.applyCoopGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('same-origin 合规', () => {
  const headers = { 'cross-origin-opener-policy': 'same-origin' };
  const r = guard.applyCoopGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('same-origin-allow-popups 合规', () => {
  const headers = { 'cross-origin-opener-policy': 'Same-Origin-Allow-Popups' };
  const r = guard.applyCoopGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('未知取值收敛为 same-origin', () => {
  const headers = { 'cross-origin-opener-policy': 'allow-everything' };
  const r = guard.applyCoopGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['cross-origin-opener-policy'], 'same-origin');
});

test('多值视为异常', () => {
  const headers = { 'cross-origin-opener-policy': ['same-origin', 'unsafe-none'] };
  const r = guard.applyCoopGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
  assert.strictEqual(headers['cross-origin-opener-policy'], 'same-origin');
});

test('空值删除', () => {
  const headers = { 'cross-origin-opener-policy': '  ' };
  const r = guard.applyCoopGuard(headers);
  assert.strictEqual(headers['cross-origin-opener-policy'], undefined);
});

test('unsafe-none 明确声明不改动', () => {
  const headers = { 'cross-origin-opener-policy': 'unsafe-none' };
  const r = guard.applyCoopGuard(headers);
  assert.strictEqual(r.changed, false);
});
