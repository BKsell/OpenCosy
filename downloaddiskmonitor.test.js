'use strict';

const test = require('node:test');
const assert = require('node:assert');
const monitor = require('./downloaddiskmonitor');

const MB = 1024 * 1024;
const GB = 1024 * 1024 * 1024;

test('monitor continues while free space is sufficient', () => {
  const clock = { t: 1000 };
  const m = monitor.createDiskMonitor({ minFreeBytes: 100 * MB, now: () => clock.t });
  const event = m.sample({ id: 'a', freeBytes: 10 * GB, totalBytes: 1 * GB, receivedBytes: 0 });
  assert.strictEqual(event.action, monitor.ACTION.CONTINUE);
  assert.strictEqual(event.reason, monitor.REASON.OK);
  assert.strictEqual(m.snapshot().tracked, 1);
  assert.strictEqual(m.snapshot().paused, 0);
});

test('monitor pauses once when free space runs low', () => {
  const m = monitor.createDiskMonitor({ minFreeBytes: 100 * MB });
  const first = m.sample({ id: 'a', freeBytes: 10 * GB, totalBytes: 5 * GB, receivedBytes: 4 * GB });
  assert.strictEqual(first.action, monitor.ACTION.CONTINUE);
  const paused = m.sample({ id: 'a', freeBytes: 300 * MB, totalBytes: 5 * GB, receivedBytes: 4 * GB });
  assert.strictEqual(paused.action, monitor.ACTION.PAUSE);
  assert.strictEqual(m.snapshot().paused, 1);
  const again = m.sample({ id: 'a', freeBytes: 300 * MB, totalBytes: 5 * GB, receivedBytes: 4 * GB });
  assert.strictEqual(again.action, monitor.ACTION.SKIP);
  assert.strictEqual(again.reason, monitor.REASON.THROTTLED);
  assert.strictEqual(m.snapshot().paused, 1);
});

test('monitor resumes only after hysteresis threshold', () => {
  const m = monitor.createDiskMonitor({ minFreeBytes: 100 * MB, resumeRatio: 2 });
  m.sample({ id: 'a', freeBytes: 10 * GB, totalBytes: 5 * GB, receivedBytes: 4 * GB });
  m.sample({ id: 'a', freeBytes: 200 * MB, totalBytes: 5 * GB, receivedBytes: 4 * GB });
  const stillLow = m.sample({ id: 'a', freeBytes: 250 * MB, totalBytes: 5 * GB, receivedBytes: 4 * GB });
  assert.strictEqual(stillLow.action, monitor.ACTION.SKIP);
  const resumed = m.sample({ id: 'a', freeBytes: 5 * GB, totalBytes: 5 * GB, receivedBytes: 4 * GB });
  assert.strictEqual(resumed.action, monitor.ACTION.RESUME);
  assert.strictEqual(m.snapshot().paused, 0);
  const after = m.sample({ id: 'a', freeBytes: 5 * GB, totalBytes: 5 * GB, receivedBytes: 4 * GB });
  assert.strictEqual(after.action, monitor.ACTION.CONTINUE);
});

test('invalid samples never pause or resume', () => {
  const m = monitor.createDiskMonitor({ minFreeBytes: 100 * MB });
  m.sample({ id: 'a', freeBytes: 10 * GB, totalBytes: 1 * GB });
  for (const freeBytes of [NaN, -1, 'x', undefined]) {
    const event = m.sample({ id: 'a', freeBytes, totalBytes: 1 * GB });
    assert.strictEqual(event.action, monitor.ACTION.SKIP);
    assert.strictEqual(event.reason, monitor.REASON.INVALID_SAMPLE);
  }
});

test('unknown ids are skipped without tracking', () => {
  const m = monitor.createDiskMonitor();
  for (const id of ['', null, undefined, 42]) {
    const event = m.sample({ id, freeBytes: 10 * GB, totalBytes: 1 * GB });
    assert.strictEqual(event.action, monitor.ACTION.SKIP);
    assert.strictEqual(event.reason, monitor.REASON.UNKNOWN_ID);
  }
  assert.strictEqual(m.snapshot().tracked, 0);
});

test('release drops a paused download from the pause count', () => {
  const m = monitor.createDiskMonitor({ minFreeBytes: 100 * MB });
  m.sample({ id: 'a', freeBytes: 10 * GB, totalBytes: 5 * GB, receivedBytes: 4 * GB });
  m.sample({ id: 'a', freeBytes: 100 * MB, totalBytes: 5 * GB, receivedBytes: 4 * GB });
  assert.strictEqual(m.snapshot().paused, 1);
  assert.strictEqual(m.release('a'), true);
  assert.strictEqual(m.snapshot().paused, 0);
  assert.strictEqual(m.release('a'), false);
});

test('tracked ids are capped and oldest entries evicted', () => {
  const m = monitor.createDiskMonitor({ minFreeBytes: 100 * MB });
  for (let index = 0; index < monitor.MAX_TRACKED_IDS + 3; index += 1) {
    m.sample({ id: `id-${index}`, freeBytes: 10 * GB, totalBytes: 1 * GB });
  }
  assert.strictEqual(m.snapshot().tracked, monitor.MAX_TRACKED_IDS);
  assert.strictEqual(m.release('id-0'), false);
  assert.strictEqual(m.release(`id-${monitor.MAX_TRACKED_IDS + 2}`), true);
});

test('notification gate obeys interval', () => {
  const clock = { t: 0 };
  const m = monitor.createDiskMonitor({ minFreeBytes: 100 * MB, notifyIntervalMs: 1000, now: () => clock.t });
  assert.strictEqual(m.shouldNotify('missing'), false);
  m.sample({ id: 'a', freeBytes: 10 * GB, totalBytes: 1 * GB });
  assert.strictEqual(m.shouldNotify('a'), true);
  m.markNotified('a');
  assert.strictEqual(m.shouldNotify('a'), false);
  clock.t = 1000;
  assert.strictEqual(m.shouldNotify('a'), true);
  assert.strictEqual(m.markNotified('missing'), false);
});

test('snapshot exposes thresholds and reset clears state', () => {
  const m = monitor.createDiskMonitor({ minFreeBytes: 100 * MB, resumeRatio: 2 });
  m.sample({ id: 'a', freeBytes: 10 * GB, totalBytes: 1 * GB });
  const snap = m.snapshot();
  assert.strictEqual(snap.minFreeBytes, 100 * MB);
  assert.strictEqual(snap.resumeFreeBytes, 200 * MB);
  assert.ok(snap.sampledAt > 0);
  m.reset();
  assert.strictEqual(m.snapshot().tracked, 0);
  assert.strictEqual(m.snapshot().freeBytes, null);
});

test('describeMonitorEvent renders each action', () => {
  assert.match(monitor.describeMonitorEvent({ action: monitor.ACTION.PAUSE, id: 'x' }), /暂停/);
  assert.match(monitor.describeMonitorEvent({ action: monitor.ACTION.RESUME, id: 'x' }), /恢复/);
  assert.match(monitor.describeMonitorEvent({ action: monitor.ACTION.CONTINUE, id: 'x' }), /充足/);
  assert.match(monitor.describeMonitorEvent({ action: monitor.ACTION.SKIP, id: 'x', reason: 'throttled' }), /无需处理/);
  assert.match(monitor.describeMonitorEvent(null), /缺失/);
});
