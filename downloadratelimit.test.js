'use strict';

const test = require('node:test');
const assert = require('node:assert');
const R = require('./downloadratelimit');

test('DownloadRateLimiter 允许窗口内的正常下载', () => {
  const limiter = new R.DownloadRateLimiter({ windowMs: 10000, perHostMax: 12, globalMax: 120 });
  for (let i = 0; i < 12; i += 1) {
    const r = limiter.record('example.test', 1000 + i);
    assert.strictEqual(r.ok, true);
  }
  assert.strictEqual(limiter.snapshot('example.test', 1011).hostCount, 12);
});

test('DownloadRateLimiter 单主机超限后拒绝', () => {
  const limiter = new R.DownloadRateLimiter({ windowMs: 10000, perHostMax: 3, globalMax: 100 });
  limiter.record('a.test', 1000);
  limiter.record('a.test', 1001);
  limiter.record('a.test', 1002);
  const blocked = limiter.record('a.test', 1003);
  assert.strictEqual(blocked.ok, false);
  assert.strictEqual(blocked.reason, R.REASON.HOST_LIMIT);
  assert.ok(blocked.retryAfterMs > 0);
});

test('DownloadRateLimiter 窗口滑出后恢复', () => {
  const limiter = new R.DownloadRateLimiter({ windowMs: 10000, perHostMax: 2, globalMax: 100 });
  limiter.record('a.test', 1000);
  limiter.record('a.test', 1001);
  assert.strictEqual(limiter.record('a.test', 1002).ok, false);
  const later = limiter.record('a.test', 11001);
  assert.strictEqual(later.ok, true);
});

test('DownloadRateLimiter 不同主机额度独立', () => {
  const limiter = new R.DownloadRateLimiter({ windowMs: 10000, perHostMax: 2, globalMax: 100 });
  limiter.record('a.test', 1000);
  limiter.record('a.test', 1001);
  assert.strictEqual(limiter.record('a.test', 1002).ok, false);
  assert.strictEqual(limiter.record('b.test', 1003).ok, true);
});

test('DownloadRateLimiter 全局上限生效', () => {
  const limiter = new R.DownloadRateLimiter({ windowMs: 10000, perHostMax: 5, globalMax: 4 });
  for (let i = 0; i < 4; i += 1) {
    assert.strictEqual(limiter.record('h' + i + '.test', 1000 + i).ok, true);
  }
  const blocked = limiter.record('h9.test', 1005);
  assert.strictEqual(blocked.ok, false);
  assert.strictEqual(blocked.reason, R.REASON.GLOBAL_LIMIT);
});

test('DownloadRateLimiter 主机名归一化与空主机桶', () => {
  const limiter = new R.DownloadRateLimiter({ windowMs: 10000, perHostMax: 1, globalMax: 100 });
  assert.strictEqual(limiter.record(' Example.TEST ', 1000).host, 'example.test');
  assert.strictEqual(limiter.record('example.test', 1001).ok, false);
  const empty = limiter.record('', 1002);
  assert.strictEqual(empty.host, '');
  assert.strictEqual(empty.ok, true);
});

test('DownloadRateLimiter reset 清空全部计数', () => {
  const limiter = new R.DownloadRateLimiter({ windowMs: 10000, perHostMax: 1, globalMax: 2 });
  limiter.record('a.test', 1000);
  limiter.record('b.test', 1001);
  assert.strictEqual(limiter.record('c.test', 1002).ok, false);
  limiter.reset();
  assert.strictEqual(limiter.snapshot('a.test', 1003).hostCount, 0);
  assert.strictEqual(limiter.record('c.test', 1004).ok, true);
});

test('describeDownloadRateLimit 覆盖全部原因码', () => {
  const codes = Object.values(R.REASON);
  const seen = new Set();
  for (const code of codes) {
    const text = R.describeDownloadRateLimit({ reason: code });
    assert.ok(text.length > 0);
    assert.ok(!seen.has(text));
    seen.add(text);
  }
  assert.ok(R.describeDownloadRateLimit({ reason: 'unknown' }).length > 0);
});
