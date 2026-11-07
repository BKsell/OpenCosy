'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./permissionsrequestguard');

test('未知权限被拒绝', () => {
  const r = guard.applyPermissionsRequestGuard({ permission: 'unknown', origin: 'https://a.example.com' });
  assert.strictEqual(r.decision, 'deny');
  assert.strictEqual(r.reason, guard.REASON.UNKNOWN_PERMISSION);
});

test('缺失 origin 被拒绝', () => {
  const r = guard.applyPermissionsRequestGuard({ permission: 'geolocation' });
  assert.strictEqual(r.decision, 'deny');
  assert.strictEqual(r.reason, guard.REASON.ORIGIN_MISSING);
});

test('非 https origin 被拒绝', () => {
  const r = guard.applyPermissionsRequestGuard({ permission: 'media', origin: 'http://a.example.com' });
  assert.strictEqual(r.decision, 'deny');
  assert.strictEqual(r.reason, guard.REASON.INSECURE_ORIGIN);
});

test('敏感权限要求确认', () => {
  const r = guard.applyPermissionsRequestGuard({ permission: 'geolocation', origin: 'https://a.example.com' });
  assert.strictEqual(r.decision, 'prompt');
  assert.strictEqual(r.reason, guard.REASON.USER_PROMPT);
});

test('持久化敏感权限被拒绝', () => {
  const r = guard.applyPermissionsRequestGuard({ permission: 'geolocation', origin: 'https://a.example.com', persist: true });
  assert.strictEqual(r.decision, 'deny');
  assert.strictEqual(r.reason, guard.REASON.PERSISTED_DENIED);
});

test('黑名单 origin 被拒绝', () => {
  const r = guard.applyPermissionsRequestGuard({ permission: 'media', origin: 'https://blocked.example.com', blockedOrigins: ['blocked.example.com'] });
  assert.strictEqual(r.decision, 'deny');
  assert.strictEqual(r.reason, guard.REASON.SENSITIVE_DENIED);
});

test('剪贴板写入主框架允许', () => {
  const r = guard.applyPermissionsRequestGuard({ permission: 'clipboard-sanitized-write', origin: 'https://a.example.com', requirePrompt: false });
  assert.strictEqual(r.decision, 'allow');
});

test('非主框架的良性权限被拒绝', () => {
  const r = guard.applyPermissionsRequestGuard({ permission: 'fullscreen', origin: 'https://a.example.com', isMainFrame: false });
  assert.strictEqual(r.decision, 'deny');
});

test('批量审计统计拒绝与确认', () => {
  const report = guard.auditPermissionBatch([
    { permission: 'geolocation', origin: 'https://a.example.com', persist: true },
    { permission: 'media', origin: 'https://a.example.com' },
    { permission: 'clipboard-sanitized-write', origin: 'https://a.example.com', requirePrompt: false },
  ]);
  assert.strictEqual(report.total, 3);
  assert.strictEqual(report.denied, 1);
  assert.strictEqual(report.prompted, 1);
});
