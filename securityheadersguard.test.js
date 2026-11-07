'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./securityheadersguard');

test('完整头集合得满分', () => {
  const r = guard.applySecurityHeadersGuard({ headers: guard.buildHeaders() });
  assert.strictEqual(r.findings.length, 0);
  assert.strictEqual(r.score, 7);
});

test('缺失 HSTS 被补上', () => {
  const r = guard.applySecurityHeadersGuard({ headers: {} });
  assert.strictEqual(r.headers['Strict-Transport-Security'].includes('max-age'), true);
  assert.ok(r.findings.some((f) => f.reason === guard.REASON.HSTS_MISSING));
});

test('缺 nosniff 被记录', () => {
  const { findings } = guard.auditHeaderBatch([{ url: 'https://a.example.com', headers: { 'Content-Security-Policy': "default-src 'self'" } }]);
  assert.ok(findings.some((f) => f.reason === guard.REASON.XCTO_MISSING || f.reason === guard.REASON.HSTS_MISSING));
});

test('无 XFO 且无 frame-ancestors 记为 frame-open', () => {
  const result = guard.applySecurityHeadersGuard({ headers: { 'Content-Security-Policy': "default-src 'self'", 'X-Content-Type-Options': 'nosniff', 'Strict-Transport-Security': 'max-age=1', 'Referrer-Policy': 'strict-origin' } });
  assert.ok(result.findings.some((f) => f.reason === guard.REASON.FRAME_OPEN));
});

test('CSP unsafe-inline 被记录', () => {
  const result = guard.applySecurityHeadersGuard({ headers: { 'Content-Security-Policy': "default-src 'self' 'unsafe-inline'" } });
  assert.ok(result.findings.some((f) => f.reason === guard.REASON.CSP_UNSAFE));
});

test('弱 Referrer-Policy 被记录', () => {
  const result = guard.applySecurityHeadersGuard({ headers: { 'Referrer-Policy': 'unsafe-url' } });
  assert.ok(result.findings.some((f) => f.reason === guard.REASON.REFERRER_WEAK));
});

test('Server 与 X-Powered-By 被删除', () => {
  const r = guard.applySecurityHeadersGuard({ headers: { Server: 'nginx', 'X-Powered-By': 'PHP', 'X-Content-Type-Options': 'nosniff' } });
  assert.strictEqual(r.headers.Server, undefined);
  assert.strictEqual(r.headers['X-Powered-By'], undefined);
});

test('批量审计统计弱头响应', () => {
  const report = guard.auditHeaderBatch([
    { url: 'https://a.example.com', headers: {} },
    { url: 'https://b.example.com', headers: guard.buildHeaders() },
  ]);
  assert.strictEqual(report.total, 2);
  assert.strictEqual(report.weak, 1);
});
