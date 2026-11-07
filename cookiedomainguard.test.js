'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./cookiedomainguard');

test('同域普通 Cookie 通过', () => {
  const r = guard.applyCookieDomainGuard('sid=abc123; Path=/; Domain=example.com; Secure; HttpOnly', 'app.example.com');
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.name, 'sid');
});

test('无 Domain 属性通过', () => {
  const r = guard.inspectSetCookie('sid=1; Path=/', 'example.com');
  assert.strictEqual(r.ok, true);
});

test('空值被拒', () => {
  const r = guard.inspectSetCookie('', 'example.com');
  assert.strictEqual(r.reason, guard.REASON.EMPTY);
});

test('格式非法被拒', () => {
  const r = guard.inspectSetCookie('novalue', 'example.com');
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('控制字符被拒', () => {
  const r = guard.inspectSetCookie('sid=1\u0007; Path=/', 'example.com');
  assert.strictEqual(r.reason, guard.REASON.CONTROL);
});

test('域不匹配被拒', () => {
  const r = guard.inspectSetCookie('sid=1; Domain=other.com', 'example.com');
  assert.strictEqual(r.reason, guard.REASON.DOMAIN_MISMATCH);
});

test('公共后缀域被拒', () => {
  const r = guard.inspectSetCookie('sid=1; Domain=com', 'example.com');
  assert.strictEqual(r.reason, guard.REASON.PUBLIC_SUFFIX);
});

test('IP 域被拒', () => {
  const r = guard.inspectSetCookie('sid=1; Domain=203.0.113.9', '203.0.113.9');
  assert.strictEqual(r.reason, guard.REASON.PUBLIC_SUFFIX);
});

test('__Host- 缺 Secure 被拒', () => {
  const r = guard.inspectSetCookie('__Host-sid=1; Path=/', 'example.com');
  assert.strictEqual(r.reason, guard.REASON.PREFIX_REQUIRES_SECURE);
});

test('__Host- 带 Domain 被拒', () => {
  const r = guard.inspectSetCookie('__Host-sid=1; Path=/; Secure; Domain=example.com', 'example.com');
  assert.strictEqual(r.reason, guard.REASON.PREFIX_REQUIRES_HOST_ONLY);
});

test('__Host- 正确写法通过', () => {
  const r = guard.inspectSetCookie('__Host-sid=1; Path=/; Secure', 'example.com');
  assert.strictEqual(r.ok, true);
});

test('__Secure- 缺 Secure 被拒', () => {
  const r = guard.inspectSetCookie('__Secure-sid=1; Path=/', 'example.com');
  assert.strictEqual(r.reason, guard.REASON.PREFIX_REQUIRES_SECURE);
});

test('SameSite=None 缺 Secure 被拒', () => {
  const r = guard.inspectSetCookie('sid=1; SameSite=None; Path=/', 'example.com');
  assert.strictEqual(r.reason, guard.REASON.SAMESITE_NONE_INSECURE);
});

test('过长 max-age 被拒', () => {
  const r = guard.inspectSetCookie('sid=1; Max-Age=999999999', 'example.com');
  assert.strictEqual(r.reason, guard.REASON.BAD_MAX_AGE);
});

test('非法 max-age 被拒', () => {
  const r = guard.inspectSetCookie('sid=1; Max-Age=abc', 'example.com');
  assert.strictEqual(r.reason, guard.REASON.BAD_MAX_AGE);
});

test('描述文本覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
