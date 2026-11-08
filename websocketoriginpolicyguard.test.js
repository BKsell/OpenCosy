'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./websocketoriginpolicyguard');

test('wss 同站放行', () => {
  const r = guard.applyWebSocketOriginPolicyGuard({ url: 'wss://chat.example.com/ws', origin: 'https://app.example.com' });
  assert.strictEqual(r.allowed, true);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('ws 明文被拒绝并给出升级目标', () => {
  const r = guard.applyWebSocketOriginPolicyGuard({ url: 'ws://chat.example.com/ws', origin: 'https://chat.example.com' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.INSECURE_WS);
  assert.strictEqual(r.rewrite, 'wss://chat.example.com/ws');
});

test('缺少 Origin 被拒绝', () => {
  const r = guard.applyWebSocketOriginPolicyGuard({ url: 'wss://chat.example.com/ws' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.ORIGIN_MISSING);
});

test('跨源 Origin 被拒绝', () => {
  const r = guard.applyWebSocketOriginPolicyGuard({ url: 'wss://chat.example.com/ws', origin: 'https://evil.example.org' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.ORIGIN_MISMATCH);
});

test('白名单内的跨源 Origin 放行', () => {
  const r = guard.applyWebSocketOriginPolicyGuard({ url: 'wss://chat.example.com/ws', origin: 'https://partner.example.org', allowedOrigins: ['https://partner.example.org'] });
  assert.strictEqual(r.allowed, true);
});

test('URL 内嵌凭据被拒绝', () => {
  const r = guard.applyWebSocketOriginPolicyGuard({ url: 'wss://user:pass@chat.example.com/ws', origin: 'https://chat.example.com' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.CREDENTIALS);
});

test('危险端口被拒绝', () => {
  const r = guard.applyWebSocketOriginPolicyGuard({ url: 'wss://chat.example.com:6379/ws', origin: 'https://chat.example.com' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.PORT_BLOCKED);
});

test('blacklist host 被拒绝', () => {
  const r = guard.applyWebSocketOriginPolicyGuard({ url: 'wss://blocked.example.com/ws', origin: 'https://blocked.example.com', blockedHosts: ['blocked.example.com'] });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.HOST_BLOCKED);
});

test('批量审计统计拒绝数', () => {
  const report = guard.auditWebSocketBatch([
    { url: 'ws://chat.example.com/ws', origin: 'https://chat.example.com' },
    { url: 'wss://chat.example.com/ws', origin: 'https://chat.example.com' },
  ]);
  assert.strictEqual(report.total, 2);
  assert.strictEqual(report.denied, 1);
});
