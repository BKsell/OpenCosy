'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./gotolinkguard');

test('普通 https 链接放行', () => {
  const r = guard.applyGotoLinkGuard({ target: 'https://example.com/path' });
  assert.strictEqual(r.allowed, true);
  assert.strictEqual(r.requiresHandoff, false);
});

test('javascript 协议被阻断', () => {
  const r = guard.applyGotoLinkGuard({ target: 'javascript:alert(1)' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.SCHEME_BLOCKED);
  assert.strictEqual(r.requiresHandoff, true);
});

test('file 协议被阻断', () => {
  const r = guard.applyGotoLinkGuard({ target: 'file:///etc/passwd' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.SCHEME_BLOCKED);
});

test('空白混淆的 javascript 被阻断', () => {
  const r = guard.applyGotoLinkGuard({ target: 'java\tscript:alert(1)' });
  assert.strictEqual(r.allowed, false);
});

test('控制字符被识别', () => {
  const r = guard.applyGotoLinkGuard({ target: 'https://example.com/\u0000path' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.NUL_BYTE);
});

test('URL 内嵌凭据被阻断', () => {
  const r = guard.applyGotoLinkGuard({ target: 'https://user:pass@example.com' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.CREDENTIALS);
});

test('mailto 外部协议放行并需确认', () => {
  const r = guard.applyGotoLinkGuard({ target: 'mailto:a@example.com' });
  assert.strictEqual(r.allowed, true);
  assert.strictEqual(r.requiresHandoff, true);
});

test('空目标被阻断', () => {
  const r = guard.applyGotoLinkGuard({ target: '   ' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.INVALID);
});

test('批量审计统计阻断数', () => {
  const report = guard.auditGotoBatch(['https://example.com', 'javascript:x', 'file:///x']);
  assert.strictEqual(report.total, 3);
  assert.strictEqual(report.blocked, 2);
});
