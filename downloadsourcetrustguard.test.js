'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./downloadsourcetrustguard');

test('可信 https 源放行', () => {
  const r = guard.applyDownloadSourceTrustGuard({ url: 'https://github.com/x/y/releases/download/v1/a.jar' });
  assert.strictEqual(r.allowed, true);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('http 源被拒', () => {
  const r = guard.applyDownloadSourceTrustGuard({ url: 'http://example.com/a.jar' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.INSECURE_ORIGIN);
});

test('仿冒域名被识别', () => {
  const r = guard.applyDownloadSourceTrustGuard({ url: 'https://githubb.com/x/a.jar' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.LOOKALIKE);
});

test('品牌子域放行', () => {
  const r = guard.applyDownloadSourceTrustGuard({ url: 'https://objects.githubusercontent.com/x' });
  assert.strictEqual(r.allowed, true);
});

test('非白名单主机被拒', () => {
  const r = guard.applyDownloadSourceTrustGuard({ url: 'https://evil.example.com/a.jar', trustedHosts: ['github.com'] });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.UNTRUSTED_ORIGIN);
});

test('跨源重定向链被拒', () => {
  const r = guard.applyDownloadSourceTrustGuard({ url: 'https://github.com/a.jar', redirectChain: ['https://evil.example.com/x'] });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.REDIRECT_CHAIN);
});

test('MIME 不符被拒', () => {
  const r = guard.applyDownloadSourceTrustGuard({ url: 'https://github.com/a.jar', expectedMime: 'application/java-archive', actualMime: 'text/html' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.MIME_MISMATCH);
});

test('缺少哈希被拒', () => {
  const r = guard.applyDownloadSourceTrustGuard({ url: 'https://github.com/a.jar', requireHash: true });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.SHA_MISSING);
});

test('批量审计统计拒绝数', () => {
  const report = guard.auditDownloadBatch([
    { url: 'https://github.com/a.jar' },
    { url: 'http://example.com/a.jar' },
  ]);
  assert.strictEqual(report.total, 2);
  assert.strictEqual(report.denied, 1);
});
