'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./pastecredentialguard');

test('普通文本放行', () => {
  const r = guard.applyPasteCredentialGuard({ text: 'hello world' });
  assert.strictEqual(r.blocked, false);
  assert.strictEqual(r.length, 11);
});

test('空粘贴被阻断', () => {
  const r = guard.applyPasteCredentialGuard({ text: '   ' });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.EMPTY);
});

test('GitHub token 被阻断', () => {
  const r = guard.applyPasteCredentialGuard({ text: 'ghp_abcdefghijklmnopqrstuvwxyz0123456789' });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.SECRET_PATTERN);
  assert.strictEqual(r.text, '');
});

test('私钥块被阻断', () => {
  const r = guard.applyPasteCredentialGuard({ text: '-----BEGIN RSA PRIVATE KEY-----\nAAA' });
  assert.strictEqual(r.blocked, true);
});

test('超长粘贴被阻断', () => {
  const r = guard.applyPasteCredentialGuard({ text: 'a'.repeat(5000) });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.TOO_LARGE);
});

test('控制字符被阻断', () => {
  const r = guard.applyPasteCredentialGuard({ text: 'abc\u0001def' });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.CONTROL_CHARS);
});

test('密码字段单行粘贴被阻断', () => {
  const r = guard.applyPasteCredentialGuard({ text: 'secret', fieldType: 'password' });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.PASSWORD_FIELD);
});

test('密码字段多行粘贴放行', () => {
  const r = guard.applyPasteCredentialGuard({ text: 'line1\nline2', fieldType: 'password', multiline: true });
  assert.strictEqual(r.blocked, false);
});

test('批量审计统计阻断数', () => {
  const report = guard.auditPasteBatch([
    { text: 'ok', fieldType: 'text' },
    { text: 'ghp_abcdefghijklmnopqrstuvwxyz0123456789', fieldType: 'text' },
  ]);
  assert.strictEqual(report.total, 2);
  assert.strictEqual(report.blocked, 1);
});
