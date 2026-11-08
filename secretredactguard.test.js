'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./secretredactguard');

test('普通文本不变更', () => {
  const r = guard.applySecretRedactGuard('页面加载完成，共 3 个标签页');
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.hits, 0);
});

test('Bearer 令牌被脱敏', () => {
  const r = guard.applySecretRedactGuard('Authorization: Bearer abcdefgh12345678');
  assert.strictEqual(r.changed, true);
  assert.ok(r.text.includes('[REDACTED]'));
  assert.ok(!r.text.includes('abcdefgh12345678'));
});

test('Basic 凭据被脱敏', () => {
  const r = guard.redactSecrets('Proxy-Authorization: Basic dXNlcjpwYXNz');
  assert.strictEqual(r.hits, 1);
  assert.ok(r.text.includes('Basic [REDACTED]'));
});

test('AWS 访问密钥被脱敏', () => {
  const r = guard.redactSecrets('key=AKIAIOSFODNN7EXAMPLE');
  assert.strictEqual(r.hits, 1);
  assert.ok(!r.text.includes('AKIAIOSFODNN7EXAMPLE'));
});

test('GitHub 令牌被脱敏', () => {
  const r = guard.redactSecrets('token ghp_abcdefghijklmnopqrstuvwxyz0123456789');
  assert.strictEqual(r.hits, 1);
});

test('Google API key 被脱敏', () => {
  const r = guard.redactSecrets('AIzaSyA1234567890abcdefghijklmnopqrstu');
  assert.strictEqual(r.hits, 1);
});

test('JWT 被脱敏', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
  const r = guard.redactSecrets('cookie: ' + jwt);
  assert.strictEqual(r.hits, 1);
  assert.ok(!r.text.includes(jwt));
});

test('私钥头被脱敏', () => {
  const r = guard.redactSecrets('-----BEGIN RSA PRIVATE KEY-----\nMIIE');
  assert.strictEqual(r.hits, 1);
});

test('password 字段被脱敏', () => {
  const r = guard.redactSecrets('password=hunter2secret');
  assert.strictEqual(r.hits, 1);
  assert.ok(!r.text.includes('hunter2secret'));
});

test('空文本被标注', () => {
  const r = guard.redactSecrets('');
  assert.strictEqual(r.reason, guard.REASON.EMPTY);
});

test('非文本被标注', () => {
  const r = guard.redactSecrets(null);
  assert.strictEqual(r.reason, guard.REASON.NOT_TEXT);
});

test('超体积被标注', () => {
  const r = guard.redactSecrets('a'.repeat(guard.MAX_BYTES + 1));
  assert.strictEqual(r.reason, guard.REASON.TOO_LARGE);
});

test('描述文本覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
