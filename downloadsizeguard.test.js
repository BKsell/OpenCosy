'use strict';

const test = require('node:test');
const assert = require('node:assert');

const guard = require('./downloadsizeguard_core');

test('normalizeLimit 把越界与脏值收敛到合法区间', () => {
  assert.strictEqual(guard.normalizeLimit(0), 0);
  assert.strictEqual(guard.normalizeLimit(-5), guard.DEFAULT_LIMIT_BYTES);
  assert.strictEqual(guard.normalizeLimit('abc'), guard.DEFAULT_LIMIT_BYTES);
  assert.strictEqual(guard.normalizeLimit(1024), guard.MIN_LIMIT_BYTES);
  assert.strictEqual(guard.normalizeLimit(guard.MAX_LIMIT_BYTES * 4), guard.MAX_LIMIT_BYTES);
  assert.strictEqual(guard.normalizeLimit(1024 * 1024 * 1024), 1024 * 1024 * 1024);
});

test('normalizeLimit 保留合法的 0（不限速语义不能被当成缺省）', () => {
  assert.strictEqual(guard.normalizeLimit(0), 0);
  const decision = guard.decideDeclared(1024, 0);
  assert.strictEqual(decision.action, guard.ACTION.ALLOW);
  assert.strictEqual(decision.reason, guard.REASON.UNLIMITED);
});

test('声明体积超过上限时在开始前取消', () => {
  const decision = guard.decideDeclared(guard.MIN_LIMIT_BYTES + 1, guard.MIN_LIMIT_BYTES);
  assert.strictEqual(decision.action, guard.ACTION.CANCEL);
  assert.strictEqual(decision.reason, guard.REASON.DECLARED_TOO_LARGE);
  assert.strictEqual(guard.decideDeclared(guard.MIN_LIMIT_BYTES, guard.MIN_LIMIT_BYTES).action, guard.ACTION.ALLOW);
});

test('声明体积未知时放行，由进度检查兜底', () => {
  const decision = guard.decideDeclared(-1, guard.MIN_LIMIT_BYTES);
  assert.strictEqual(decision.action, guard.ACTION.ALLOW);
  assert.strictEqual(guard.decideProgress(guard.MIN_LIMIT_BYTES + 1, guard.MIN_LIMIT_BYTES).action, guard.ACTION.CANCEL);
});

test('进度超过上限时取消，返回原因可读', () => {
  const decision = guard.decideProgress(guard.MIN_LIMIT_BYTES + 4096, guard.MIN_LIMIT_BYTES);
  assert.strictEqual(decision.action, guard.ACTION.CANCEL);
  assert.strictEqual(decision.reason, guard.REASON.GROWING_TOO_LARGE);
  assert.strictEqual(guard.decideProgress(guard.MIN_LIMIT_BYTES, guard.MIN_LIMIT_BYTES).action, guard.ACTION.ALLOW);
  assert.match(guard.describe(decision), /超过上限/);
});

test('describe 与 formatBytes 给出人类可读的大小', () => {
  assert.strictEqual(guard.formatBytes(0), '0 B');
  assert.strictEqual(guard.formatBytes(512), '512 B');
  assert.strictEqual(guard.formatBytes(1536), '1.5 KB');
  assert.strictEqual(guard.formatBytes(8 * 1024 * 1024 * 1024), '8 GB');
  assert.match(guard.describe({ action: guard.ACTION.ALLOW, reason: guard.REASON.UNLIMITED }), /已关闭/);
  assert.match(guard.describe({ action: guard.ACTION.ALLOW, reason: guard.REASON.OK }), /上限内/);
});
