'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./navigationdowngradeguard');

test('同源 https 导航放行', () => {
  const r = guard.applyNavigationDowngradeGuard({ from: 'https://a.example.com/x', to: 'https://a.example.com/y' });
  assert.strictEqual(r.blocked, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.strictEqual(r.url, 'https://a.example.com/y');
});

test('https 到 http 降级被阻断', () => {
  const r = guard.applyNavigationDowngradeGuard({ from: 'https://a.example.com', to: 'http://a.example.com/login' });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.DOWNGRADE);
});

test('wss 到 ws 降级被阻断', () => {
  const r = guard.applyNavigationDowngradeGuard({ from: 'wss://a.example.com/ws', to: 'ws://a.example.com/ws' });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.DOWNGRADE);
});

test('非法 URL 被阻断', () => {
  const r = guard.applyNavigationDowngradeGuard({ from: 'https://a.example.com', to: 'not a url' });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.INVALID);
});

test('危险 scheme 被阻断', () => {
  const r = guard.applyNavigationDowngradeGuard({ to: 'file:///etc/passwd' });
  assert.strictEqual(r.blocked, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
  const bad = guard.applyNavigationDowngradeGuard({ to: 'ftp://example.com/x' });
  assert.strictEqual(bad.blocked, true);
  assert.strictEqual(bad.reason, guard.REASON.SCHEME_BLOCKED);
});

test('URL 内嵌凭据被清理并阻断', () => {
  const r = guard.applyNavigationDowngradeGuard({ to: 'https://user:pass@example.com/x' });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.CREDENTIALS);
  assert.strictEqual(r.url.includes('user'), false);
});

test('回环地址明文放行', () => {
  const r = guard.applyNavigationDowngradeGuard({ to: 'http://127.0.0.1:8080/x' });
  assert.strictEqual(r.blocked, false);
  assert.strictEqual(r.reason, guard.REASON.HTTP_PLAINTEXT);
});

test('strict 模式把明文升级为 https', () => {
  const r = guard.applyNavigationDowngradeGuard({ to: 'http://example.org/x', options: { strict: true } });
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.url, 'https://example.org/x');
});

test('批量审计统计阻断与重写', () => {
  const report = guard.auditNavigationBatch([
    { from: 'https://a.example.com', to: 'http://a.example.com' },
    { from: 'https://a.example.com', to: 'https://b.example.org' },
    { to: 'http://127.0.0.1/x' },
  ]);
  assert.strictEqual(report.total, 3);
  assert.strictEqual(report.blocked, 1);
  assert.ok(report.findings.length >= 1);
  assert.ok(guard.describeFindings(report.findings).includes(guard.REASON.DOWNGRADE));
});

test('站点判定按二级域名', () => {
  assert.strictEqual(guard.isSameSite('a.example.com', 'b.example.com'), true);
  assert.strictEqual(guard.isSameSite('example.com', 'example.org'), false);
});
