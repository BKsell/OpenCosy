'use strict';

const test = require('node:test');
const assert = require('node:assert');
const disk = require('./downloaddiskspace');

const GB = 1024 * 1024 * 1024;

test('required reserve grows with file size and respects ceiling', () => {
  assert.strictEqual(disk.requiredReserve(0), disk.MIN_FREE_BYTES);
  assert.strictEqual(disk.requiredReserve(100 * 1024 * 1024), disk.MIN_FREE_BYTES);
  assert.strictEqual(disk.requiredReserve(10 * GB), Math.ceil(10 * GB * disk.RESERVE_RATIO));
  assert.strictEqual(disk.requiredReserve(1000 * GB), disk.MAX_RESERVE_BYTES);
  assert.strictEqual(disk.requiredFreeBytes(3 * GB), 3 * GB + disk.requiredReserve(3 * GB));
});

test('safeBytes never returns negative or fractional values', () => {
  assert.strictEqual(disk.safeBytes(-5), 0);
  assert.strictEqual(disk.safeBytes(NaN), 0);
  assert.strictEqual(disk.safeBytes(1.9), 1);
  assert.strictEqual(disk.safeBytes('2048'), 2048);
  assert.strictEqual(disk.safeBytes(Number.MAX_SAFE_INTEGER * 4), Number.MAX_SAFE_INTEGER);
});

test('allow path when space is plentiful', () => {
  const decision = disk.evaluateSpace({ freeBytes: 20 * GB, totalBytes: 2 * GB });
  assert.strictEqual(decision.action, disk.ACTION.ALLOW);
  assert.strictEqual(decision.reason, disk.REASON.OK);
  assert.strictEqual(decision.shortfallBytes, 0);
});

test('block when file exceeds free space', () => {
  const decision = disk.evaluateSpace({ freeBytes: 1 * GB, totalBytes: 3 * GB });
  assert.strictEqual(decision.action, disk.ACTION.BLOCK);
  assert.strictEqual(decision.reason, disk.REASON.INSUFFICIENT);
  assert.ok(decision.shortfallBytes > 0);
});

test('warn when the download fits but leaves no safety margin', () => {
  const decision = disk.evaluateSpace({ freeBytes: 3.5 * GB, totalBytes: 3 * GB });
  assert.strictEqual(decision.action, disk.ACTION.WARN);
  assert.strictEqual(decision.reason, disk.REASON.LOW_FREE);
  const blocked = disk.evaluateSpace({ freeBytes: 100 * 1024 * 1024, totalBytes: 1024 * 1024 });
  assert.strictEqual(blocked.action, disk.ACTION.BLOCK);
  assert.strictEqual(blocked.reason, disk.REASON.INSUFFICIENT);
});

test('warn when server omits content length', () => {
  const decision = disk.evaluateSpace({ freeBytes: 5 * GB, totalBytes: 0 });
  assert.strictEqual(decision.action, disk.ACTION.WARN);
  assert.strictEqual(decision.reason, disk.REASON.UNKNOWN_SIZE);
  const tight = disk.evaluateSpace({ freeBytes: disk.MIN_FREE_BYTES - 1, totalBytes: 0 });
  assert.strictEqual(tight.action, disk.ACTION.BLOCK);
});

test('invalid free space reading blocks instead of guessing', () => {
  for (const freeBytes of [NaN, -1, undefined, 'x']) {
    const decision = disk.evaluateSpace({ freeBytes, totalBytes: 1024 });
    assert.strictEqual(decision.action, disk.ACTION.BLOCK);
    assert.strictEqual(decision.reason, disk.REASON.INVALID);
  }
});

test('existing partial bytes are counted against the budget', () => {
  const freeBytes = 6 * GB;
  const withExisting = disk.evaluateSpace({ freeBytes, totalBytes: 4 * GB, existingBytes: 2 * GB });
  assert.strictEqual(withExisting.action, disk.ACTION.BLOCK);
  const withoutExisting = disk.evaluateSpace({ freeBytes, totalBytes: 4 * GB });
  assert.strictEqual(withoutExisting.action, disk.ACTION.ALLOW);
});

test('progress pauses only when remaining bytes cannot be met', () => {
  const pause = disk.evaluateProgress({ freeBytes: 300 * 1024 * 1024, totalBytes: 2 * GB, receivedBytes: 1 * GB });
  assert.strictEqual(pause.action, disk.PROGRESS.PAUSE);
  assert.strictEqual(pause.reason, disk.REASON.PAUSED_LOW_FREE);
  assert.ok(pause.remainingBytes > 0);
  const go = disk.evaluateProgress({ freeBytes: 10 * GB, totalBytes: 2 * GB, receivedBytes: 1 * GB });
  assert.strictEqual(go.action, disk.PROGRESS.CONTINUE);
});

test('cleanup plan frees oldest partial downloads first', () => {
  const plan = disk.planCleanup({
    freeBytes: 100 * 1024 * 1024,
    needBytes: 2 * GB,
    candidates: [
      { path: '/tmp/new.part', size: 1500 * 1024 * 1024, updatedAt: 300 },
      { path: '/tmp/old.part', size: 900 * 1024 * 1024, updatedAt: 100 },
      { path: '/tmp/mid.part', size: 200 * 1024 * 1024, updatedAt: 200 },
      { path: '', size: 500 },
      { path: '/tmp/zero.part', size: 0 },
    ],
  });
  assert.strictEqual(plan.ready, true);
  assert.deepStrictEqual(plan.entries.map((entry) => entry.path), ['/tmp/old.part', '/tmp/mid.part', '/tmp/new.part']);
  assert.strictEqual(plan.freedBytes, 2600 * 1024 * 1024);
});

test('cleanup plan reports shortfall when candidates are insufficient', () => {
  const plan = disk.planCleanup({
    freeBytes: 0,
    needBytes: 4 * GB,
    candidates: [{ path: '/tmp/a.part', size: 1024 * 1024 }],
  });
  assert.strictEqual(plan.ready, false);
  assert.ok(plan.shortfallBytes > 0);
});

test('describeDecision covers every branch', () => {
  assert.match(disk.describeDecision({ reason: disk.REASON.OK, freeBytes: 1 }), /满足/);
  assert.match(disk.describeDecision({ reason: disk.REASON.INSUFFICIENT, freeBytes: 1, shortfallBytes: 10 }), /不足/);
  assert.match(disk.describeDecision({ reason: disk.REASON.LOW_FREE, freeBytes: 1 }), /阈值/);
  assert.match(disk.describeDecision({ reason: disk.REASON.UNKNOWN_SIZE }), /未提供/);
  assert.match(disk.describeDecision({ reason: disk.REASON.INVALID }), /无法读取/);
  assert.match(disk.describeDecision({ reason: disk.REASON.PAUSED_LOW_FREE, freeBytes: 1 }), /暂停/);
  assert.match(disk.describeDecision(null), /未知/);
});

test('disk report aggregates scan outcomes', () => {
  const report = disk.auditDiskReport({ scanned: 10, failed: 2, lowFree: 1 });
  assert.deepStrictEqual(report, {
    total: 10, ok: 7, lowFree: 1, failed: 2, healthy: false, reasons: ['scan-failed', 'low-free', 'ok'],
  });
  const clean = disk.auditDiskReport({ scanned: 3, failed: 0, lowFree: 0 });
  assert.strictEqual(clean.healthy, true);
  assert.deepStrictEqual(clean.reasons, ['ok']);
});

test('formatBytes selects sensible units', () => {
  assert.strictEqual(disk.formatBytes(0), '0 B');
  assert.strictEqual(disk.formatBytes(2048), '2.0 KiB');
  assert.strictEqual(disk.formatBytes(5 * 1024 * 1024), '5.0 MiB');
  assert.match(disk.formatBytes(3 * GB), /GiB/);
});
