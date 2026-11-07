'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./telemetryconsentguard');

test('无同意阻断', () => {
  const r = guard.applyTelemetryConsentGuard({ endpoint: 'https://t.example.com' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.NO_CONSENT);
});

test('已退出阻断', () => {
  const r = guard.applyTelemetryConsentGuard({ consent: true, optedOut: true });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.OPT_OUT);
});

test('敏感字段阻断', () => {
  const r = guard.applyTelemetryConsentGuard({ consent: true, fields: ['email', 'event'] });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.SENSITIVE_FIELD);
  assert.deepStrictEqual(r.fields, ['email']);
});

test('稳定标识符阻断', () => {
  const r = guard.applyTelemetryConsentGuard({ consent: true, stableIdentifier: 'machine-id', identifierRotated: false });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.IDENTIFIER);
});

test('标识符轮换后放行', () => {
  const r = guard.applyTelemetryConsentGuard({ consent: true, stableIdentifier: 'daily-uuid', identifierRotated: true });
  assert.strictEqual(r.allowed, true);
});

test('跨境端点阻断', () => {
  const r = guard.applyTelemetryConsentGuard({ consent: true, endpointHosts: ['collect.example.cn'] });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.CROSS_BORDER);
});

test('payload 白名单剥离敏感键', () => {
  const r = guard.sanitizePayload({ event: 'start', email: 'a@b.com', ip: '1.2.3.4' }, { allowFields: ['event'] });
  assert.deepStrictEqual(r.payload, { event: 'start' });
  assert.strictEqual(r.dropped.length, 2);
});

test('放行时返回净化 payload', () => {
  const r = guard.applyTelemetryConsentGuard({ consent: true, payload: { event: 'start', token: 'x' } });
  assert.strictEqual(r.allowed, true);
  assert.strictEqual(r.payload.token, undefined);
  assert.strictEqual(r.dropped.includes('token'), true);
});

test('批量审计统计阻断数', () => {
  const report = guard.auditTelemetryBatch([
    { consent: true, endpoint: 'https://t.example.com' },
    { endpoint: 'https://t.example.com' },
  ]);
  assert.strictEqual(report.total, 2);
  assert.strictEqual(report.blocked, 1);
});
