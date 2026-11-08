'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./proxyauthenticateguard');

test('缺头不改动', () => {
  const r = guard.applyProxyAuthenticateGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('Digest 合规', () => {
  const headers = { 'proxy-authenticate': 'Digest realm="proxy", nonce="abc"' };
  const r = guard.applyProxyAuthenticateGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('Basic 被视为弱方案', () => {
  const headers = { 'proxy-authenticate': 'Basic realm="proxy"' };
  const r = guard.applyProxyAuthenticateGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.WEAK_SCHEME);
  assert.strictEqual(headers['proxy-authenticate'], undefined);
});

test('未知方案被拒', () => {
  const headers = { 'proxy-authenticate': 'Sneaky realm="x"' };
  const r = guard.applyProxyAuthenticateGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['proxy-authenticate'], undefined);
});

test('控制字符删除', () => {
  const headers = { 'proxy-authenticate': 'Digest realm="p"\u0000' };
  const r = guard.applyProxyAuthenticateGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});

test('参数过多截断', () => {
  const pairs = Array.from({ length: 10 }, (_, i) => `p${i}=v`);
  const headers = { 'proxy-authenticate': `Digest ${pairs.join(', ')}` };
  const r = guard.applyProxyAuthenticateGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
});

test('空值删除', () => {
  const headers = { 'proxy-authenticate': '' };
  const r = guard.applyProxyAuthenticateGuard(headers);
  assert.strictEqual(headers['proxy-authenticate'], undefined);
});
