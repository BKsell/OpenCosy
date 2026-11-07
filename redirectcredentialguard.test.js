'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./redirectcredentialguard');

test('同源重定向保留凭据', () => {
  const headers = { Authorization: 'Bearer token', Cookie: 'sid=1' };
  const r = guard.applyRedirectCredentialGuard({ from: 'https://a.example.com/x', to: 'https://a.example.com/y', headers });
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.SAME_ORIGIN);
  assert.strictEqual(headers.Authorization, 'Bearer token');
  assert.strictEqual(headers.Cookie, 'sid=1');
});

test('跨源重定向剥离凭据头', () => {
  const headers = { Authorization: 'Bearer token', Cookie: 'sid=1', 'Proxy-Authorization': 'Basic x', Accept: 'text/html' };
  const r = guard.applyRedirectCredentialGuard({ from: 'https://a.example.com/x', to: 'https://b.example.com/y', headers });
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.CROSS_ORIGIN);
  assert.deepStrictEqual(r.stripped.sort(), ['authorization', 'cookie', 'proxy-authorization']);
  assert.strictEqual(headers.Authorization, undefined);
  assert.strictEqual(headers.Cookie, undefined);
  assert.strictEqual(headers.Accept, 'text/html');
});

test('跨子域视作跨源', () => {
  const r = guard.evaluateRedirect({ from: 'https://a.example.com/', to: 'https://sub.a.example.com/', headers: {} });
  assert.strictEqual(r.reason, guard.REASON.CROSS_ORIGIN);
});

test('HTTPS 降级被拒', () => {
  const r = guard.applyRedirectCredentialGuard({ from: 'https://a.example.com/', to: 'http://a.example.com/', headers: { Cookie: 'sid=1' } });
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.DOWNGRADE);
});

test('HTTP 到 HTTPS 升级放行', () => {
  const r = guard.evaluateRedirect({ from: 'http://a.example.com/', to: 'https://a.example.com/', headers: {} });
  assert.strictEqual(r.allowed, true);
  assert.strictEqual(r.reason, guard.REASON.UPGRADE);
});

test('非法地址被拒', () => {
  const r = guard.applyRedirectCredentialGuard({ from: 'not-a-url', to: 'https://a.example.com/', headers: {} });
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.INVALID);
});

test('缺少参数被拒', () => {
  const r = guard.evaluateRedirect(null);
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.INVALID);
});

test('同源不同端口视作跨源', () => {
  const r = guard.evaluateRedirect({ from: 'https://a.example.com/', to: 'https://a.example.com:8443/', headers: {} });
  assert.strictEqual(r.reason, guard.REASON.CROSS_ORIGIN);
});

test('描述文本覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
