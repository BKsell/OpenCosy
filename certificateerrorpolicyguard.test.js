'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./certificateerrorpolicyguard');

test('过期证书被阻断', () => {
  const r = guard.applyCertificateErrorPolicyGuard({ host: 'a.example.com', cert: { validTo: '2020-01-01T00:00:00Z', trusted: true } });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.EXPIRED);
});

test('主机名不匹配被阻断', () => {
  const r = guard.applyCertificateErrorPolicyGuard({ host: 'a.example.com', cert: { validTo: '2030-01-01T00:00:00Z', subjectName: 'b.example.com', trusted: true } });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.HOSTNAME_MISMATCH);
});

test('SAN 覆盖时放行', () => {
  const r = guard.applyCertificateErrorPolicyGuard({ host: 'a.example.com', cert: { validTo: '2030-01-01T00:00:00Z', subjectName: 'b.example.com', san: ['a.example.com'], trusted: true } });
  assert.strictEqual(r.action, 'allow');
});

test('自签名证书被阻断', () => {
  const r = guard.applyCertificateErrorPolicyGuard({ host: 'a.example.com', cert: { validTo: '2030-01-01T00:00:00Z', selfSigned: true, trusted: true } });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.SELF_SIGNED);
});

test('弱签名算法被阻断', () => {
  const r = guard.applyCertificateErrorPolicyGuard({ host: 'a.example.com', cert: { validTo: '2030-01-01T00:00:00Z', signatureAlgorithm: 'sha1', trusted: true } });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.WEAK_SIGNATURE);
});

test('不受信任链需要确认', () => {
  const r = guard.applyCertificateErrorPolicyGuard({ host: 'a.example.com', cert: { validTo: '2030-01-01T00:00:00Z', trusted: false } });
  assert.strictEqual(r.action, 'confirm');
  assert.strictEqual(r.showInterstitial, true);
});

test('HSTS 主机不能例外', () => {
  const r = guard.applyCertificateErrorPolicyGuard({ host: 'a.example.com', hstsHost: true, cert: { validTo: '2030-01-01T00:00:00Z', trusted: false } });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.HSTS_HOST);
});

test('缺少证书被阻断', () => {
  const r = guard.applyCertificateErrorPolicyGuard({ host: 'a.example.com' });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.UNTRUSTED_CHAIN);
});

test('用户绕过未授权时阻断', () => {
  const r = guard.applyCertificateErrorPolicyGuard({ host: 'a.example.com', bypass: true, cert: { validTo: '2030-01-01T00:00:00Z', trusted: true } });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.USER_BYPASS);
});

test('批量审计统计阻断数', () => {
  const report = guard.auditCertificateBatch([
    { host: 'a.example.com', cert: { validTo: '2030-01-01T00:00:00Z', trusted: true } },
    { host: 'b.example.com', cert: { validTo: '2020-01-01T00:00:00Z', trusted: true } },
  ]);
  assert.strictEqual(report.total, 2);
  assert.strictEqual(report.blocked, 1);
});
