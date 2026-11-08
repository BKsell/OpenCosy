'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./corpguard');

test('缺头不改动', () => {
  const r = guard.applyCorpGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('same-origin 合规', () => {
  const headers = { 'cross-origin-resource-policy': 'same-origin' };
  const r = guard.applyCorpGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('same-site 合规', () => {
  const headers = { 'cross-origin-resource-policy': 'Same-Site' };
  const r = guard.applyCorpGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('cross-origin 收敛为 same-origin', () => {
  const headers = { 'cross-origin-resource-policy': 'cross-origin' };
  const r = guard.applyCorpGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.WEAK);
  assert.strictEqual(headers['cross-origin-resource-policy'], 'same-origin');
});

test('未知取值收敛', () => {
  const headers = { 'cross-origin-resource-policy': 'allow-all' };
  const r = guard.applyCorpGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});

test('多值收敛', () => {
  const headers = { 'cross-origin-resource-policy': ['same-origin', 'same-site'] };
  const r = guard.applyCorpGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
});

test('空值删除', () => {
  const headers = { 'cross-origin-resource-policy': '' };
  const r = guard.applyCorpGuard(headers);
  assert.strictEqual(headers['cross-origin-resource-policy'], undefined);
});
