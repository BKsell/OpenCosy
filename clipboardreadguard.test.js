'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./clipboardreadguard');

test('合法读取放行', () => {
  const r = guard.applyClipboardReadGuard({ origin: 'https://a.example.com', userGesture: true, text: 'hello' });
  assert.strictEqual(r.allowed, true);
  assert.strictEqual(r.text, 'hello');
});

test('缺失 origin 被拒', () => {
  const r = guard.applyClipboardReadGuard({ userGesture: true, text: 'x' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.ORIGIN_MISSING);
});

test('http origin 被拒', () => {
  const r = guard.applyClipboardReadGuard({ origin: 'http://a.example.com', userGesture: true, text: 'x' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.INSECURE_ORIGIN);
});

test('无用户手势被拒', () => {
  const r = guard.applyClipboardReadGuard({ origin: 'https://a.example.com', text: 'x' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.NO_GESTURE);
});

test('超长文本被拒', () => {
  const r = guard.applyClipboardReadGuard({ origin: 'https://a.example.com', userGesture: true, text: 'a'.repeat(40000) });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.TOO_LARGE);
});

test('未知类型被拒', () => {
  const r = guard.applyClipboardReadGuard({ origin: 'https://a.example.com', userGesture: true, types: ['application/octet-stream'] });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.UNKNOWN_TYPE);
});

test('含 token 的剪贴板被拒', () => {
  const r = guard.applyClipboardReadGuard({ origin: 'https://a.example.com', userGesture: true, text: 'ghp_abcdefghijklmnopqrstuvwxyz0123456789' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.SECRET_CONTENT);
  assert.strictEqual(r.redacted, true);
  assert.strictEqual(r.text, '');
});

test('授权后可读敏感内容', () => {
  const r = guard.applyClipboardReadGuard({ origin: 'https://a.example.com', userGesture: true, text: 'a@b.com', allowSecret: true });
  assert.strictEqual(r.allowed, true);
});

test('批量审计统计拒绝数', () => {
  const report = guard.auditClipboardBatch([
    { origin: 'https://a.example.com', userGesture: true, text: 'ok' },
    { origin: 'https://a.example.com', text: 'no gesture' },
  ]);
  assert.strictEqual(report.total, 2);
  assert.strictEqual(report.denied, 1);
});
