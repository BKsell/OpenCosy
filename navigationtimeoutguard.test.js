'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./navigationtimeoutguard');

test('合法超时保持', () => {
  const r = guard.applyNavigationTimeoutGuard({ timeout: 30000 });
  assert.strictEqual(r.timeout, 30000);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('过小超时抬到下限', () => {
  const r = guard.applyNavigationTimeoutGuard({ timeout: 1000 });
  assert.strictEqual(r.timeout, 3000);
  assert.strictEqual(r.reason, guard.REASON.TOO_SHORT);
});

test('过大超时压到上限', () => {
  const r = guard.applyNavigationTimeoutGuard({ timeout: 999999 });
  assert.strictEqual(r.timeout, 120000);
  assert.strictEqual(r.reason, guard.REASON.TOO_LONG);
});

test('非法超时回落默认值', () => {
  const r = guard.applyNavigationTimeoutGuard({ timeout: 'abc' });
  assert.strictEqual(r.timeout, 30000);
  assert.strictEqual(r.reason, guard.REASON.INVALID);
});

test('重试次数超限被阻断', () => {
  const r = guard.applyNavigationTimeoutGuard({ timeout: 30000, retries: 5 });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.RETRY_EXHAUSTED);
});

test('慢主机降级超时并回退', () => {
  const r = guard.applyNavigationTimeoutGuard({ timeout: 60000, host: 'slow.example.com', slowHosts: ['slow.example.com'] });
  assert.strictEqual(r.timeout, 15000);
  assert.strictEqual(r.backoff, true);
  assert.strictEqual(r.reason, guard.REASON.SLOW_HOST);
});

test('负重试次数被阻断', () => {
  const r = guard.applyNavigationTimeoutGuard({ timeout: 30000, retries: -1 });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.INVALID);
});

test('重试次数上限为 3', () => {
  const r = guard.applyNavigationTimeoutGuard({ timeout: 30000, retries: 4 });
  assert.strictEqual(r.retriesAllowed, 3);
});

test('批量审计统计异常项', () => {
  const report = guard.auditTimeoutBatch([
    { timeout: 30000 },
    { timeout: 1000 },
    { timeout: 999999 },
  ]);
  assert.strictEqual(report.total, 3);
  assert.strictEqual(report.clamped, 2);
});
