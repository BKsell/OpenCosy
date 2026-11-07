'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./upgradeinsecureguard');

test('https 保持原样', () => {
  const r = guard.upgrade('https://a.example.com/x');
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('http 升级为 https', () => {
  const r = guard.upgrade('http://a.example.com/x');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.url, 'https://a.example.com/x');
  assert.strictEqual(r.reason, guard.REASON.UPGRADED);
});

test('80 端口被移除', () => {
  const r = guard.upgrade('http://a.example.com:80/x');
  assert.strictEqual(r.url, 'https://a.example.com/x');
});

test('回环地址保持明文', () => {
  const r = guard.upgrade('http://127.0.0.1:8080/x');
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.LOCAL_OK);
});

test('非法 URL 返回 INVALID', () => {
  const r = guard.upgrade('not-a-url');
  assert.strictEqual(r.reason, guard.REASON.INVALID);
});

test('未允许升级时阻断', () => {
  const r = guard.applyUpgradeInsecureGuard({ url: 'http://a.example.com/x' });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.upgradeTo, 'https://a.example.com/x');
});

test('允许升级时改写', () => {
  const r = guard.applyUpgradeInsecureGuard({ url: 'http://a.example.com/x', allowUpgrade: true });
  assert.strictEqual(r.blocked, false);
  assert.strictEqual(r.url, 'https://a.example.com/x');
});

test('https 响应加 HSTS 头', () => {
  const r = guard.applyUpgradeInsecureGuard({ url: 'https://a.example.com', headers: {} });
  assert.strictEqual(r.headers['Strict-Transport-Security'], 'max-age=31536000; includeSubDomains');
});

test('批量审计统计升级与阻断', () => {
  const report = guard.auditInsecureBatch([
    { url: 'http://a.example.com' },
    { url: 'http://a.example.com', allowUpgrade: true },
    { url: 'https://b.example.com' },
  ]);
  assert.strictEqual(report.total, 3);
  assert.strictEqual(report.upgraded, 1);
  assert.strictEqual(report.blocked, 1);
});
