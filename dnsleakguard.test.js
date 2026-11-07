'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./dnsleakguard');

test('同站 preconnect 放行', () => {
  const r = guard.applyDnsLeakGuard({ url: 'https://cdn.example.com', pageUrl: 'https://www.example.com', rel: 'preconnect' });
  assert.strictEqual(r.allowed, true);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('跨站 dns-prefetch 被剔除', () => {
  const r = guard.applyDnsLeakGuard({ url: 'https://tracker.example.org', pageUrl: 'https://www.example.com', rel: 'dns-prefetch' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.PREFETCH_CROSS_SITE);
  assert.strictEqual(r.action, 'strip');
});

test('跨站 prefetch 被剔除', () => {
  const r = guard.applyDnsLeakGuard({ url: 'https://ads.example.org/x', pageUrl: 'https://www.example.com', rel: 'prefetch' });
  assert.strictEqual(r.allowed, false);
});

test('跟踪器主机被剔除', () => {
  const r = guard.applyDnsLeakGuard({ url: 'https://www.google-analytics.com/collect', pageUrl: 'https://www.example.com', rel: 'preconnect' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.TRACKER_HOST);
});

test('明文 DNS 被剔除', () => {
  const r = guard.applyDnsLeakGuard({ url: 'http://resolver.example.com/dns-query', pageUrl: 'https://www.example.com', rel: 'preconnect' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.DNS_OVER_HTTP);
});

test('CNAME 伪装被识别', () => {
  const r = guard.applyDnsLeakGuard({ url: 'https://cdn.example.com/x', pageUrl: 'https://cdn.example.com', rel: 'preconnect', cnameTarget: 'https://track.example.org' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.CNAME_CLOAKING);
});

test('非法 URL 被剔除', () => {
  const r = guard.applyDnsLeakGuard({ url: 'not-a-url', rel: 'preconnect' });
  assert.strictEqual(r.allowed, false);
});

test('批量审计统计剔除数', () => {
  const report = guard.auditDnsBatch([
    { url: 'https://cdn.example.com', pageUrl: 'https://www.example.com', rel: 'preconnect' },
    { url: 'https://www.google-analytics.com/x', pageUrl: 'https://www.example.com', rel: 'preconnect' },
  ]);
  assert.strictEqual(report.total, 2);
  assert.strictEqual(report.stripped, 1);
});
