'use strict';

const test = require('node:test');
const assert = require('node:assert');
const protocolRate = require('./protocolrate');

test('前三次放行，第四次在同一窗口内被限流', () => {
  const limiter = protocolRate.createLimiter({ windowMs: 60000, maxPerWindow: 3, duplicateWindowMs: 0 });
  const now = 1000;
  for (let i = 0; i < 3; i += 1) {
    const r = protocolRate.check(limiter, 'https://a.test', 'mailto:', 'mailto:x@a.test?i=' + i, now + i);
    assert.equal(r.ok, true, '第 ' + (i + 1) + ' 次应放行');
  }
  const blocked = protocolRate.check(limiter, 'https://a.test', 'mailto:', 'mailto:x@a.test?i=9', now + 10);
  assert.equal(blocked.ok, false);
  assert.equal(blocked.reason, 'rate-limited');
  assert.ok(blocked.retryAfterMs > 0 && blocked.retryAfterMs <= 60000);
});

test('窗口滑过后重新放行', () => {
  const limiter = protocolRate.createLimiter({ windowMs: 1000, maxPerWindow: 1, duplicateWindowMs: 0 });
  assert.equal(protocolRate.check(limiter, 'https://b.test', 'tel:', 'tel:1', 0).ok, true);
  assert.equal(protocolRate.check(limiter, 'https://b.test', 'tel:', 'tel:2', 500).ok, false);
  assert.equal(protocolRate.check(limiter, 'https://b.test', 'tel:', 'tel:3', 1001).ok, true);
});

test('同一 URL 短时间重复被去重，不同 URL 不互斥', () => {
  const limiter = protocolRate.createLimiter({ windowMs: 60000, maxPerWindow: 9, duplicateWindowMs: 2000 });
  const first = protocolRate.check(limiter, 'https://c.test', 'mailto:', 'mailto:z@c.test', 10000);
  assert.equal(first.ok, true);
  const dup = protocolRate.check(limiter, 'https://c.test', 'mailto:', 'mailto:z@c.test', 11000);
  assert.equal(dup.ok, false);
  assert.equal(dup.reason, 'duplicate');
  const other = protocolRate.check(limiter, 'https://c.test', 'mailto:', 'mailto:y@c.test', 11500);
  assert.equal(other.ok, true);
});

test('不同 origin 各自独立计数', () => {
  const limiter = protocolRate.createLimiter({ windowMs: 60000, maxPerWindow: 1, duplicateWindowMs: 0 });
  assert.equal(protocolRate.check(limiter, 'https://d1.test', 'tel:', 'tel:1', 0).ok, true);
  assert.equal(protocolRate.check(limiter, 'https://d2.test', 'tel:', 'tel:2', 0).ok, true);
  assert.equal(protocolRate.check(limiter, 'https://d1.test', 'tel:', 'tel:3', 0).ok, false);
});

test('describeReason 覆盖两种拒绝', () => {
  assert.equal(protocolRate.describeReason('duplicate'), '重复的协议唤起请求');
  assert.equal(protocolRate.describeReason('rate-limited'), '外部协议唤起过于频繁');
  assert.equal(protocolRate.describeReason(''), '');
});
