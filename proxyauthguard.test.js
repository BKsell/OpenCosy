'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./proxyauthguard');

const HTTPS = { url: 'https://example.com/a' };
const HTTP = { url: 'http://example.com/a' };

test('无认证头不改动', () => {
  const headers = { 'content-type': ['text/html'] };
  const r = guard.applyProxyAuthGuard(headers, HTTPS);
  assert.strictEqual(r.changed, false);
});

test('Proxy-Authenticate 被剥离', () => {
  const headers = { 'Proxy-Authenticate': ['Basic realm=proxy'] };
  const r = guard.applyProxyAuthGuard(headers, HTTPS);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.findings[0].reason, guard.REASON.PROXY_HEADER);
  assert.strictEqual(headers['Proxy-Authenticate'], undefined);
});

test('Proxy-Authorization 与 Info 一并剥离', () => {
  const headers = { 'proxy-authorization': ['Basic x'], 'proxy-authentication-info': ['next'] };
  const r = guard.applyProxyAuthGuard(headers, HTTPS);
  assert.strictEqual(r.findings.length, 2);
});

test('明文链路上的 Basic 挑战被剥离', () => {
  const headers = { 'www-authenticate': ['Basic realm="intranet"'] };
  const r = guard.applyProxyAuthGuard(headers, HTTP);
  assert.strictEqual(r.findings[0].reason, guard.REASON.INSECURE_BASIC);
  assert.strictEqual(headers['www-authenticate'], undefined);
});

test('HTTPS 上的 Basic 挑战保留', () => {
  const headers = { 'www-authenticate': ['Basic realm="x"'] };
  const r = guard.applyProxyAuthGuard(headers, HTTPS);
  assert.strictEqual(r.changed, false);
  assert.ok(headers['www-authenticate']);
});

test('NTLM 在 HTTPS 保留', () => {
  const headers = { 'www-authenticate': ['NTLM'] };
  const r = guard.applyProxyAuthGuard(headers, HTTPS);
  assert.strictEqual(r.changed, false);
});

test('IP 字面量上的 NTLM 被剥离', () => {
  const headers = { 'www-authenticate': ['Negotiate'] };
  const r = guard.applyProxyAuthGuard(headers, { url: 'https://10.0.0.5/a' });
  assert.strictEqual(r.findings[0].reason, guard.REASON.NTLM_LEAK);
});

test('结构非法整条剥离', () => {
  const headers = { 'www-authenticate': ['@bad scheme'] };
  const r = guard.applyProxyAuthGuard(headers, HTTPS);
  assert.strictEqual(r.findings[0].reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers['www-authenticate'], undefined);
});

test('超长挑战剥离', () => {
  const headers = { 'www-authenticate': ['Basic ' + 'a'.repeat(300)] };
  const r = guard.applyProxyAuthGuard(headers, HTTPS);
  assert.strictEqual(r.findings[0].reason, guard.REASON.MALFORMED);
});

test('挑战过多剥离', () => {
  const headers = { 'www-authenticate': ['Basic, Bearer, Digest, Negotiate, NTLM, Hawk'] };
  const r = guard.applyProxyAuthGuard(headers, HTTPS);
  assert.strictEqual(r.findings[0].reason, guard.REASON.TOO_MANY);
});

test('引号内逗号不被切断', () => {
  const parsed = guard.parseChallenges('Basic realm="a,b", Bearer');
  assert.strictEqual(parsed.length, 2);
  assert.strictEqual(parsed[0].scheme, 'basic');
});

test('空段视为非法', () => {
  assert.strictEqual(guard.parseChallenges('Basic,,'), null);
});

test('describeReason 覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
