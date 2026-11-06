'use strict';

const test = require('node:test');
const assert = require('node:assert');
const quota = require('./downloadquota');

test('reserve accepts known-good host', () => {
  const q = new quota.DownloadQuota();
  const res = q.reserve('Example.COM', 1024);
  assert.strictEqual(res.ok, true);
  assert.strictEqual(res.reason, quota.REASON.OK);
  assert.strictEqual(res.host, 'example.com');
  assert.strictEqual(res.reservedBytes, 1024);
  assert.strictEqual(q.snapshot().totalBytes, 1024);
});

test('reserve rejects malformed hosts', () => {
  const q = new quota.DownloadQuota();
  for (const host of ['', ' ', null, undefined, 12, 'bad host', 'http://x', 'a'.repeat(254), '-abc']) {
    const res = q.reserve(host, 1);
    assert.strictEqual(res.ok, false);
    assert.strictEqual(res.reason, quota.REASON.INVALID_HOST);
  }
});

test('reserve rejects malformed byte counts', () => {
  const q = new quota.DownloadQuota();
  for (const bytes of [-1, NaN, Infinity, '1024', null, 1.5 * Number.MAX_SAFE_INTEGER]) {
    const res = q.reserve('example.com', bytes);
    assert.strictEqual(res.ok, false);
    assert.strictEqual(res.reason, quota.REASON.INVALID_BYTES);
  }
});

test('global budget blocks oversize reservation', () => {
  const q = new quota.DownloadQuota({ globalMaxBytes: 1000 });
  assert.strictEqual(q.reserve('a.test', 400).ok, true);
  assert.strictEqual(q.reserve('b.test', 400).ok, true);
  const blocked = q.reserve('c.test', 400);
  assert.strictEqual(blocked.ok, false);
  assert.strictEqual(blocked.reason, quota.REASON.GLOBAL_EXCEEDED);
});

test('per host budget blocks oversize reservation', () => {
  const q = new quota.DownloadQuota({ hostMaxBytes: 500 });
  assert.strictEqual(q.reserve('a.test', 400).ok, true);
  const blocked = q.reserve('a.test', 200);
  assert.strictEqual(blocked.ok, false);
  assert.strictEqual(blocked.reason, quota.REASON.HOST_EXCEEDED);
  assert.strictEqual(q.reserve('b.test', 200).ok, true);
});

test('host count is bounded', () => {
  const q = new quota.DownloadQuota({ maxHosts: 2 });
  assert.strictEqual(q.reserve('a.test', 1).ok, true);
  assert.strictEqual(q.reserve('b.test', 1).ok, true);
  const blocked = q.reserve('c.test', 1);
  assert.strictEqual(blocked.ok, false);
  assert.strictEqual(blocked.reason, quota.REASON.TOO_MANY_HOSTS);
  assert.strictEqual(q.reserve('a.test', 1).ok, true);
});

test('settle adjusts reservation to actual size', () => {
  const q = new quota.DownloadQuota({ globalMaxBytes: 1000 });
  const res = q.reserve('a.test', 100);
  assert.strictEqual(q.settle('a.test', res.reservedBytes, 250), true);
  assert.strictEqual(q.snapshot().totalBytes, 250);
  assert.strictEqual(q.settle('a.test', 250, 50), true);
  assert.strictEqual(q.snapshot().totalBytes, 50);
});

test('settle refuses to grow beyond budget', () => {
  const q = new quota.DownloadQuota({ globalMaxBytes: 1000 });
  q.reserve('a.test', 900);
  assert.strictEqual(q.settle('a.test', 900, 1500), false);
  assert.strictEqual(q.snapshot().totalBytes, 900);
});

test('settle rejects unknown host and inconsistent reservation', () => {
  const q = new quota.DownloadQuota();
  assert.strictEqual(q.settle('missing.test', 10, 10), false);
  q.reserve('a.test', 10);
  assert.strictEqual(q.settle('a.test', 20, 20), false);
});

test('release frees bytes and drops empty hosts', () => {
  const q = new quota.DownloadQuota();
  q.reserve('a.test', 100);
  assert.strictEqual(q.release('a.test', 40), true);
  assert.strictEqual(q.snapshot().totalBytes, 60);
  assert.strictEqual(q.release('a.test', 60), true);
  assert.strictEqual(q.snapshot().totalBytes, 0);
  assert.strictEqual(q.snapshot().hostCount, 0);
  assert.strictEqual(q.release('a.test', 1), false);
});

test('zero byte reservations are allowed even at full budget', () => {
  const q = new quota.DownloadQuota({ globalMaxBytes: 100 });
  q.reserve('a.test', 100);
  const res = q.reserve('b.test', 0);
  assert.strictEqual(res.ok, true);
  assert.strictEqual(res.reason, quota.REASON.OK);
});

test('snapshot exposes host map without leaking internals', () => {
  const q = new quota.DownloadQuota();
  q.reserve('a.test', 10);
  const snap = q.snapshot();
  assert.deepStrictEqual(snap.hosts, { 'a.test': 10 });
  snap.hosts['a.test'] = 999;
  assert.strictEqual(q.snapshot().hosts['a.test'], 10);
});

test('describe rejects are unique and non empty', () => {
  const reasons = [
    quota.REASON.OK,
    quota.REASON.INVALID_HOST,
    quota.REASON.INVALID_BYTES,
    quota.REASON.GLOBAL_EXCEEDED,
    quota.REASON.HOST_EXCEEDED,
    quota.REASON.TOO_MANY_HOSTS,
  ];
  const seen = new Set();
  for (const reason of reasons) {
    const msg = quota.describeQuotaReject(reason, 'a.test');
    assert.ok(msg.length > 0);
    assert.ok(!seen.has(msg), `duplicate message for ${reason}`);
    seen.add(msg);
  }
  assert.ok(quota.describeQuotaReject('unknown', '').length > 0);
});
