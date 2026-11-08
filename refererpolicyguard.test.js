'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./refererpolicyguard');

test('同源 strict-origin-when-cross-origin 发送完整 URL', () => {
  const r = guard.buildReferer('https://a.example.com/page?q=1', 'https://a.example.com/next', 'strict-origin-when-cross-origin');
  assert.strictEqual(r.value, 'https://a.example.com/page?q=1');
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('跨源只发送 origin', () => {
  const r = guard.buildReferer('https://a.example.com/page?token=1', 'https://b.example.org/x', 'strict-origin-when-cross-origin');
  assert.strictEqual(r.value, 'https://a.example.com/');
  assert.strictEqual(r.reason, guard.REASON.ORIGIN_ONLY);
});

test('https 到 http 完全剥离', () => {
  const r = guard.buildReferer('https://a.example.com/page', 'http://b.example.org/x', 'strict-origin-when-cross-origin');
  assert.strictEqual(r.value, '');
  assert.strictEqual(r.reason, guard.REASON.STRIPPED);
});

test('no-referrer 始终为空', () => {
  const r = guard.buildReferer('https://a.example.com/page', 'https://a.example.com/x', 'no-referrer');
  assert.strictEqual(r.value, '');
});

test('策略名非法时回退到默认策略', () => {
  const r = guard.buildReferer('https://a.example.com/page', 'https://b.example.org/x', 'weird-policy');
  assert.strictEqual(r.value, 'https://a.example.com/');
});

test('非法源 URL 返回 INVALID', () => {
  const r = guard.buildReferer('not-a-url', 'https://b.example.org', 'strict-origin');
  assert.strictEqual(r.reason, guard.REASON.INVALID);
});

test('apply 写入或删除 Referer 头', () => {
  const headers = { Referer: 'https://leak.example.com/page?token=abc' };
  const r = guard.applyRefererPolicyGuard({ sourceUrl: 'https://a.example.com/page', targetUrl: 'http://b.example.org', policy: 'strict-origin-when-cross-origin', headers });
  assert.strictEqual(r.headers.Referer, undefined);
  assert.strictEqual(r.changed, true);
});

test('stripSensitiveQuery 去掉查询与片段', () => {
  const r = guard.stripSensitiveQuery('https://a.example.com/p?token=secret#frag');
  assert.strictEqual(r.value, 'https://a.example.com/p');
  assert.strictEqual(r.changed, true);
});

test('批量审计统计剥离数', () => {
  const report = guard.auditRefererBatch([
    { sourceUrl: 'https://a.example.com/p', targetUrl: 'http://b.example.org', policy: 'strict-origin' },
    { sourceUrl: 'https://a.example.com/p', targetUrl: 'https://a.example.com/q', policy: 'strict-origin' },
  ]);
  assert.strictEqual(report.total, 2);
  assert.strictEqual(report.stripped, 1);
});
