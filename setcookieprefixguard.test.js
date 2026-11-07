'use strict';

const test = require('node:test');
const assert = require('node:assert');

const guard = require('./setcookieprefixguard');

test('未下发 Set-Cookie 时不动', () => {
  const headers = {};
  const result = guard.applySetCookiePrefixGuard(headers);
  assert.strictEqual(result.changed, false);
  assert.strictEqual(result.reason, guard.REASON.MISSING);
});

test('合规 Cookie 保持原样', () => {
  const value = 'sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax';
  const headers = { 'Set-Cookie': value };
  const result = guard.applySetCookiePrefixGuard(headers);
  assert.strictEqual(result.changed, false);
  assert.strictEqual(headers['Set-Cookie'], value);
});

test('缺 SameSite 补 Lax', () => {
  const headers = { 'Set-Cookie': 'sid=abc; Path=/; Secure; HttpOnly' };
  const result = guard.applySetCookiePrefixGuard(headers);
  assert.strictEqual(result.changed, true);
  assert.ok(headers['Set-Cookie'].includes('SameSite=Lax'));
  assert.strictEqual(result.reason, guard.REASON.SAMESITE_MISSING);
});

test('SameSite=None 缺 Secure 降级', () => {
  const headers = { 'Set-Cookie': 'sid=abc; Path=/; SameSite=None' };
  const result = guard.applySetCookiePrefixGuard(headers);
  assert.strictEqual(headers['Set-Cookie'].includes('SameSite=Lax'), true);
  assert.strictEqual(result.reason, guard.REASON.NONE_WITHOUT_SECURE);
});

test('SameSite=None 带 Secure 保留', () => {
  const headers = { 'Set-Cookie': 'sid=abc; Path=/; Secure; SameSite=None' };
  const result = guard.applySetCookiePrefixGuard(headers);
  assert.strictEqual(result.changed, false);
});

test('非法 SameSite 改 Lax', () => {
  const headers = { 'Set-Cookie': 'sid=abc; SameSite=Weird; Secure' };
  const result = guard.applySetCookiePrefixGuard(headers);
  assert.strictEqual(result.reason, guard.REASON.BAD_SAMESITE);
  assert.ok(headers['Set-Cookie'].includes('SameSite=Lax'));
});

test('__Host- 带 Domain 被移除', () => {
  const headers = { 'Set-Cookie': '__Host-sid=abc; Domain=example.com; Path=/; Secure; SameSite=Lax' };
  const result = guard.applySetCookiePrefixGuard(headers);
  assert.strictEqual(headers['Set-Cookie'].includes('Domain'), false);
  assert.strictEqual(result.reason, guard.REASON.HOST_PREFIX_VIOLATION);
});

test('__Host- 缺 Secure 自动补齐', () => {
  const headers = { 'Set-Cookie': '__Host-sid=abc; Path=/; SameSite=Lax' };
  guard.applySetCookiePrefixGuard(headers);
  assert.ok(headers['Set-Cookie'].includes('Secure'));
  assert.ok(headers['Set-Cookie'].includes('Path=/'));
});

test('__Host- Path 非根被修正', () => {
  const headers = { 'Set-Cookie': '__Host-sid=abc; Path=/app; Secure; SameSite=Lax' };
  guard.applySetCookiePrefixGuard(headers);
  assert.strictEqual(headers['Set-Cookie'].includes('Path=/app'), false);
  assert.ok(headers['Set-Cookie'].includes('Path=/'));
});

test('__Secure- 缺 Secure 被补齐', () => {
  const headers = { 'Set-Cookie': '__Secure-sid=abc; Path=/; SameSite=Lax' };
  const result = guard.applySetCookiePrefixGuard(headers);
  assert.strictEqual(result.reason, guard.REASON.SECURE_PREFIX_VIOLATION);
  assert.ok(headers['Set-Cookie'].includes('Secure'));
});

test('缺 HttpOnly 仅记录不重写', () => {
  const headers = { 'Set-Cookie': 'sid=abc; Path=/; Secure; SameSite=Lax' };
  const result = guard.applySetCookiePrefixGuard(headers);
  assert.strictEqual(result.changed, false);
  assert.strictEqual(result.reason, guard.REASON.NOT_HTTPONLY);
});

test('重复属性被记录', () => {
  const headers = { 'Set-Cookie': 'sid=abc; Path=/; Path=/; Secure; HttpOnly; SameSite=Lax' };
  const result = guard.applySetCookiePrefixGuard(headers);
  assert.ok(result.findings.some((f) => f.reason === guard.REASON.DUP_ATTRIBUTE));
});

test('非法 Cookie 名被丢弃', () => {
  const headers = { 'Set-Cookie': 'bad name=abc; Path=/' };
  const result = guard.applySetCookiePrefixGuard(headers);
  assert.strictEqual('Set-Cookie' in headers, false);
  assert.strictEqual(result.reason, guard.REASON.MALFORMED);
});

test('空 Cookie 被丢弃', () => {
  const headers = { 'Set-Cookie': '   ' };
  guard.applySetCookiePrefixGuard(headers);
  assert.strictEqual('Set-Cookie' in headers, false);
});

test('超长 Cookie 被丢弃', () => {
  const headers = { 'Set-Cookie': 'sid=' + 'a'.repeat(guard.MAX_COOKIE_LENGTH) };
  guard.applySetCookiePrefixGuard(headers);
  assert.strictEqual('Set-Cookie' in headers, false);
});

test('数组多 Cookie 保留全部', () => {
  const headers = {
    'Set-Cookie': ['a=1; Path=/; Secure; HttpOnly; SameSite=Lax', 'b=2; Path=/; Secure; HttpOnly; SameSite=Lax'],
  };
  const result = guard.applySetCookiePrefixGuard(headers);
  assert.strictEqual(headers['Set-Cookie'].length, 2);
  assert.strictEqual(result.changed, false);
});

test('未知属性被记录为非法', () => {
  const headers = { 'Set-Cookie': 'sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax; Weird=1' };
  const result = guard.applySetCookiePrefixGuard(headers);
  assert.strictEqual(result.reason, guard.REASON.BAD_NAME);
});

test('Priority 属性保留大小写规范', () => {
  const headers = { 'Set-Cookie': 'sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax; Priority=High' };
  const result = guard.applySetCookiePrefixGuard(headers);
  assert.strictEqual(result.changed, false);
});

test('describeReason 覆盖全部原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});

test('sanitizeCookie 解析名值', () => {
  const parsed = guard.sanitizeCookie('sid=abc; Path=/');
  assert.strictEqual(parsed.reason, guard.REASON.SAMESITE_MISSING);
  assert.ok(parsed.cookie.includes('SameSite=Lax'));
});
