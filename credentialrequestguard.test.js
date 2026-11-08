'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./credentialrequestguard');

test('空地址视为非法', () => {
  const r = guard.inspectCredentialRequest('');
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('无依赖方标识时仅校验来源', () => {
  const r = guard.inspectCredentialRequest('https://example.com/login');
  assert.strictEqual(r.allowed, true);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('依赖方标识与主机完全一致允许', () => {
  const r = guard.inspectCredentialRequest('https://example.com/login', { rpId: 'example.com' });
  assert.strictEqual(r.allowed, true);
});

test('依赖方标识为可注册父域允许子域', () => {
  const r = guard.inspectCredentialRequest('https://login.example.com/', { rpId: 'example.com' });
  assert.strictEqual(r.allowed, true);
});

test('依赖方标识与主机不匹配拒绝', () => {
  const r = guard.inspectCredentialRequest('https://evil.com/', { rpId: 'example.com' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.RP_ID_MISMATCH);
});

test('跨两级子域不匹配拒绝', () => {
  const r = guard.inspectCredentialRequest('https://a.b.example.com/', { rpId: 'example.com' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.RP_ID_MISMATCH);
});

test('公共后缀依赖方标识拒绝', () => {
  const r = guard.inspectCredentialRequest('https://example.com/', { rpId: 'com' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.RP_ID_SUFFIX_AMBIGUOUS);
});

test('punycode 依赖方标识拒绝', () => {
  const r = guard.inspectCredentialRequest('https://xn--80ak6aa92e.com/', { rpId: 'xn--80ak6aa92e.com' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.PUNYCODE_RP_ID);
});

test('明文 HTTP 远程来源拒绝', () => {
  const r = guard.inspectCredentialRequest('http://example.com/', { rpId: 'example.com' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE_SCHEME);
});

test('本地 HTTP 允许', () => {
  const r = guard.inspectCredentialRequest('http://localhost:3000/', { rpId: 'localhost' });
  assert.strictEqual(r.allowed, true);
});

test('file 来源视为不透明', () => {
  const r = guard.inspectCredentialRequest('file:///C:/app/index.html');
  assert.strictEqual(r.reason, guard.REASON.OPAQUE_ORIGIN);
});

test('内嵌凭据拒绝', () => {
  const r = guard.inspectCredentialRequest('https://user:pass@example.com/');
  assert.strictEqual(r.reason, guard.REASON.EMBEDDED_CREDENTIALS);
});

test('超长地址拒绝', () => {
  const r = guard.inspectCredentialRequest(`https://example.com/${'a'.repeat(2100)}`);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});

test('依赖方标识大小写与前导点归一化', () => {
  const r = guard.inspectCredentialRequest('https://example.com/', { rpId: '.EXAMPLE.COM.' });
  assert.strictEqual(r.allowed, true);
});

test('apply 包装返回 changed', () => {
  const ok = guard.applyCredentialRequestGuard('https://example.com/', { rpId: 'example.com' });
  assert.strictEqual(ok.changed, false);
  const bad = guard.applyCredentialRequestGuard('https://evil.com/', { rpId: 'example.com' });
  assert.strictEqual(bad.changed, true);
});

test('describeReason 覆盖主要状态', () => {
  assert.strictEqual(typeof guard.describeReason(guard.REASON.OK), 'string');
  assert.strictEqual(typeof guard.describeReason('unknown'), 'string');
});
