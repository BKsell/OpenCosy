'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./coepguard');

test('缺头不改动', () => {
  const r = guard.applyCoepGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('require-corp 合规', () => {
  const headers = { 'cross-origin-embedder-policy': ['require-corp'] };
  const r = guard.applyCoepGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('credentialless 合规', () => {
  const headers = { 'cross-origin-embedder-policy': 'credentialless' };
  const r = guard.applyCoepGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('未知取值收敛为 require-corp', () => {
  const headers = { 'cross-origin-embedder-policy': 'allow-all' };
  const r = guard.applyCoepGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['cross-origin-embedder-policy'], 'require-corp');
});

test('重复取值收敛为 require-corp', () => {
  const headers = { 'cross-origin-embedder-policy': ['require-corp', 'credentialless'] };
  const r = guard.applyCoepGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
  assert.strictEqual(headers['cross-origin-embedder-policy'], 'require-corp');
});

test('空值删除', () => {
  const headers = { 'cross-origin-embedder-policy': '' };
  const r = guard.applyCoepGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers['cross-origin-embedder-policy'], undefined);
});
