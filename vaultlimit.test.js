'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createUnlockLimiter } = require('./vaultlimit_core');

function fakeClock() {
  let t = 0;
  return { now: () => t, advance: ms => { t += ms; } };
}

test('失败次数达到阈值后开始封锁，冷却期内 check 返回 locked-out', () => {
  const clock = fakeClock();
  const limiter = createUnlockLimiter({ now: clock.now, maxFailures: 3, baseDelayMs: 1000, maxDelayMs: 8000 });
  assert.strictEqual(limiter.check().ok, true);
  limiter.fail();
  limiter.fail();
  assert.strictEqual(limiter.check().ok, true);
  assert.strictEqual(limiter.fail().retryAfterMs, 1000);
  const gate = limiter.check();
  assert.strictEqual(gate.ok, false);
  assert.strictEqual(gate.reason, 'locked-out');
  clock.advance(999);
  assert.strictEqual(limiter.check().ok, false);
  clock.advance(1);
  assert.strictEqual(limiter.check().ok, true);
});

test('冷却时间指数增长并封顶，reset 后恢复通行', () => {
  const clock = fakeClock();
  const limiter = createUnlockLimiter({ now: clock.now, maxFailures: 2, baseDelayMs: 1000, maxDelayMs: 4000 });
  assert.strictEqual(limiter.fail().retryAfterMs, 0);
  assert.strictEqual(limiter.fail().retryAfterMs, 1000);
  clock.advance(1000);
  assert.strictEqual(limiter.fail().retryAfterMs, 2000);
  clock.advance(2000);
  assert.strictEqual(limiter.fail().retryAfterMs, 4000);
  clock.advance(4000);
  assert.strictEqual(limiter.fail().retryAfterMs, 4000);
  limiter.reset();
  assert.strictEqual(limiter.check().ok, true);
  assert.strictEqual(limiter.snapshot().failures, 0);
});

test('非法参数回落到默认阈值与冷却', () => {
  const limiter = createUnlockLimiter({ maxFailures: 0, baseDelayMs: -1 });
  for (let i = 0; i < 4; i += 1) limiter.fail();
  assert.strictEqual(limiter.check().ok, true);
  assert.strictEqual(limiter.fail().retryAfterMs, 30000);
  assert.strictEqual(limiter.check().ok, false);
});
