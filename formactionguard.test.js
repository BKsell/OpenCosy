'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./formactionguard');

test('同源 https action 放行', () => {
  const r = guard.applyFormActionGuard({ action: 'https://a.example.com/submit', pageUrl: 'https://a.example.com/form' });
  assert.strictEqual(r.action, 'allow');
  assert.strictEqual(r.requireConfirm, false);
});

test('空 action 回落到页面地址', () => {
  const r = guard.applyFormActionGuard({ pageUrl: 'https://a.example.com/form' });
  assert.strictEqual(r.action, 'allow');
  assert.strictEqual(r.url, 'https://a.example.com/form');
});

test('javascript action 被阻断', () => {
  const r = guard.applyFormActionGuard({ action: 'javascript:void(0)', pageUrl: 'https://a.example.com' });
  assert.strictEqual(r.action, 'block');
  assert.strictEqual(r.reason, guard.REASON.JAVASCRIPT);
});

test('https 页面提交到 http 被阻断', () => {
  const r = guard.applyFormActionGuard({ action: 'http://a.example.com/submit', pageUrl: 'https://a.example.com' });
  assert.strictEqual(r.action, 'block');
  assert.strictEqual(r.reason, guard.REASON.INSECURE);
});

test('跨源 action 需确认', () => {
  const r = guard.applyFormActionGuard({ action: 'https://pay.example.org/submit', pageUrl: 'https://a.example.com' });
  assert.strictEqual(r.action, 'rewrite');
  assert.strictEqual(r.requireConfirm, true);
});

test('含文件输入的跨源提交被阻断', () => {
  const r = guard.applyFormActionGuard({ action: 'https://evil.example.org/upload', pageUrl: 'https://a.example.com', hasFileInput: true });
  assert.strictEqual(r.action, 'block');
  assert.strictEqual(r.reason, guard.REASON.FILES_EXFIL);
});

test('action 内嵌凭据被阻断', () => {
  const r = guard.applyFormActionGuard({ action: 'https://u:p@a.example.com/submit', pageUrl: 'https://a.example.com' });
  assert.strictEqual(r.action, 'block');
  assert.strictEqual(r.reason, guard.REASON.CREDENTIALS);
});

test('非 http 协议被阻断', () => {
  const r = guard.applyFormActionGuard({ action: 'ftp://a.example.com/x', pageUrl: 'https://a.example.com' });
  assert.strictEqual(r.action, 'block');
  assert.strictEqual(r.reason, guard.REASON.INVALID);
});

test('批量审计统计阻断与确认', () => {
  const report = guard.auditFormBatch([
    { action: 'javascript:x', pageUrl: 'https://a.example.com' },
    { action: 'https://pay.example.org/x', pageUrl: 'https://a.example.com' },
    { action: 'https://a.example.com/x', pageUrl: 'https://a.example.com' },
  ]);
  assert.strictEqual(report.total, 3);
  assert.strictEqual(report.blocked, 1);
  assert.strictEqual(report.confirm, 1);
});
