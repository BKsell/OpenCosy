'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./notificationpolicyguard');

test('合法通知放行', () => {
  const r = guard.applyNotificationPolicyGuard({ origin: 'https://a.example.com', title: 'Hi', body: 'done' });
  assert.strictEqual(r.allowed, true);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.strictEqual(r.silent, false);
});

test('缺失 origin 被拒', () => {
  const r = guard.applyNotificationPolicyGuard({ title: 'Hi' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.ORIGIN_MISSING);
});

test('http origin 被拒', () => {
  const r = guard.applyNotificationPolicyGuard({ origin: 'http://a.example.com', title: 'Hi' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.INSECURE_ORIGIN);
});

test('静音来源被拒', () => {
  const r = guard.applyNotificationPolicyGuard({ origin: 'https://a.example.com', mutedOrigins: ['a.example.com'] });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.MUTED_ORIGIN);
});

test('重复通知被限流', () => {
  const r = guard.applyNotificationPolicyGuard({ origin: 'https://a.example.com', pendingCount: 6 });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.RATE_LIMITED);
});

test('超长 tag 被拒', () => {
  const r = guard.applyNotificationPolicyGuard({ origin: 'https://a.example.com', tag: 'a-b'.repeat(20) });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.TAG_ABUSE);
});

test('正文邮箱被脱敏并静音', () => {
  const r = guard.applyNotificationPolicyGuard({ origin: 'https://a.example.com', title: 'Hi', body: 'mail a@b.com' });
  assert.strictEqual(r.allowed, true);
  assert.strictEqual(r.reason, guard.REASON.SENSITIVE_BODY);
  assert.strictEqual(r.body.includes('a@b.com'), false);
  assert.strictEqual(r.silent, true);
});

test('正文长数字被脱敏', () => {
  const r = guard.applyNotificationPolicyGuard({ origin: 'https://a.example.com', body: 'code 123456789' });
  assert.strictEqual(r.body.includes('123456789'), false);
});

test('批量审计统计阻断与脱敏', () => {
  const report = guard.auditNotificationBatch([
    { origin: 'https://a.example.com', title: 'ok' },
    { origin: 'http://b.example.com', title: 'x' },
    { origin: 'https://c.example.com', body: 'mail c@d.com' },
  ]);
  assert.strictEqual(report.total, 3);
  assert.strictEqual(report.blocked, 1);
  assert.strictEqual(report.sanitized, 1);
});
