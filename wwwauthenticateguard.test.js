'use strict';

const test = require('node:test');
const assert = require('node:assert');

const guard = require('./wwwauthenticateguard');

test('缺失时不改动', () => {
  const headers = {};
  const result = guard.applyWwwAuthenticateGuard(headers, 'WWW-Authenticate');
  assert.strictEqual(result.changed, false);
  assert.strictEqual(result.reason, guard.REASON.MISSING);
});

test('Basic realm 合法保留', () => {
  const headers = { 'WWW-Authenticate': 'Basic realm="restricted"' };
  const result = guard.applyWwwAuthenticateGuard(headers, 'WWW-Authenticate');
  assert.strictEqual(result.changed, false);
  assert.strictEqual(result.challenges, 1);
});

test('Bearer 无参数保留', () => {
  const headers = { 'WWW-Authenticate': 'Bearer' };
  const result = guard.applyWwwAuthenticateGuard(headers, 'WWW-Authenticate');
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('Bearer 带 error 参数保留', () => {
  const headers = { 'WWW-Authenticate': 'Bearer error="invalid_token", error_description="expired"' };
  const result = guard.applyWwwAuthenticateGuard(headers, 'WWW-Authenticate');
  assert.strictEqual(result.changed, false);
});

test('含 CRLF 的挑战被移除', () => {
  const headers = { 'WWW-Authenticate': 'Basic realm="x"\r\nX-Injected: 1' };
  const result = guard.applyWwwAuthenticateGuard(headers, 'WWW-Authenticate');
  assert.strictEqual(result.reason, guard.REASON.CONTROL_CHAR);
  assert.strictEqual('WWW-Authenticate' in headers, false);
});

test('非法方案名被移除', () => {
  const headers = { 'WWW-Authenticate': 'Ba sic realm="x"' };
  guard.applyWwwAuthenticateGuard(headers, 'WWW-Authenticate');
  assert.strictEqual('WWW-Authenticate' in headers, false);
});

test('realm 引号不闭合被移除', () => {
  const headers = { 'WWW-Authenticate': 'Basic realm="unterminated' };
  const result = guard.applyWwwAuthenticateGuard(headers, 'WWW-Authenticate');
  assert.strictEqual(result.reason, guard.REASON.BAD_REALM);
  assert.strictEqual('WWW-Authenticate' in headers, false);
});

test('超长挑战被移除', () => {
  const headers = { 'WWW-Authenticate': 'Basic realm="' + 'a'.repeat(guard.MAX_LENGTH) + '"' };
  const result = guard.applyWwwAuthenticateGuard(headers, 'WWW-Authenticate');
  assert.strictEqual(result.reason, guard.REASON.OVERLONG);
});

test('过多挑战头被移除', () => {
  const headers = { 'WWW-Authenticate': ['Basic realm="a"', 'Bearer', 'Negotiate', 'Digest', 'NTLM'] };
  const result = guard.applyWwwAuthenticateGuard(headers, 'WWW-Authenticate');
  assert.strictEqual(result.reason, guard.REASON.TOO_MANY);
  assert.strictEqual('WWW-Authenticate' in headers, false);
});

test('Proxy-Authenticate 同样受控', () => {
  const headers = { 'Proxy-Authenticate': 'Basic realm="proxy"' };
  const result = guard.applyWwwAuthenticateGuard(headers, 'Proxy-Authenticate');
  assert.strictEqual(result.changed, false);
  assert.strictEqual(result.challenges, 1);
});

test('参数缺等号被移除', () => {
  const headers = { 'WWW-Authenticate': 'Basic realm' };
  const result = guard.applyWwwAuthenticateGuard(headers, 'WWW-Authenticate');
  assert.strictEqual(result.reason, guard.REASON.MALFORMED);
});

test('空挑战被移除', () => {
  const headers = { 'WWW-Authenticate': '   ' };
  guard.applyWwwAuthenticateGuard(headers, 'WWW-Authenticate');
  assert.strictEqual('WWW-Authenticate' in headers, false);
});

test('parseChallenge 处理非字符串', () => {
  const parsed = guard.parseChallenge(null);
  assert.strictEqual(parsed.reason, guard.REASON.MALFORMED);
});

test('describeReason 覆盖全部原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
