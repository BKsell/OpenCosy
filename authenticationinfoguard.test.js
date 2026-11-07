'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./authenticationinfoguard');

const GOOD = 'qop=auth, rspauth="abcdef1234==", cnonce="c0ffee", nc=00000001';

test('缺省头不动作', () => {
  const headers = {};
  const result = guard.applyAuthenticationInfoGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(result.reason, guard.REASON.MISSING);
});

test('合法参数保留', () => {
  const headers = { 'Authentication-Info': GOOD };
  const result = guard.applyAuthenticationInfoGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(headers['Authentication-Info'], GOOD);
});

test('nextnonce 保留', () => {
  const headers = { 'authentication-info': 'nextnonce="n-123", qop=auth' };
  const result = guard.applyAuthenticationInfoGuard(headers);
  assert.equal(result.changed, false);
});

test('控制字符被删除', () => {
  const headers = { 'Authentication-Info': 'qop=auth,\r\nX-Injected: 1' };
  const result = guard.applyAuthenticationInfoGuard(headers);
  assert.equal(result.reason, guard.REASON.CONTROL_CHARS);
  assert.equal(headers['Authentication-Info'], undefined);
});

test('未知参数被删除', () => {
  const headers = { 'Authentication-Info': 'qop=auth, sessid=abc' };
  const result = guard.applyAuthenticationInfoGuard(headers);
  assert.equal(result.reason, guard.REASON.UNKNOWN_PARAM);
});

test('rspauth 非 base64 被删除', () => {
  const headers = { 'Authentication-Info': 'rspauth="not***base64"' };
  const result = guard.applyAuthenticationInfoGuard(headers);
  assert.equal(result.reason, guard.REASON.BAD_BASE64);
});

test('nc 长度非法被删除', () => {
  const headers = { 'Authentication-Info': 'qop=auth, nc=1234' };
  const result = guard.applyAuthenticationInfoGuard(headers);
  assert.equal(result.reason, guard.REASON.BAD_NC);
});

test('qop 非法被删除', () => {
  const headers = { 'Authentication-Info': 'qop=none' };
  const result = guard.applyAuthenticationInfoGuard(headers);
  assert.equal(result.reason, guard.REASON.BAD_QOP);
});

test('nextnonce 超长被删除', () => {
  const headers = { 'Authentication-Info': `nextnonce="${'n'.repeat(200)}"` };
  const result = guard.applyAuthenticationInfoGuard(headers);
  assert.equal(result.reason, guard.REASON.NONCE_TOO_LONG);
});

test('超长取值被删除', () => {
  const headers = { 'Authentication-Info': `qop=auth, cnonce="${'c'.repeat(520)}"` };
  const result = guard.applyAuthenticationInfoGuard(headers);
  assert.equal(result.reason, guard.REASON.OVERLONG);
});

test('缺少等号被删除', () => {
  const headers = { 'Authentication-Info': 'qop' };
  const result = guard.applyAuthenticationInfoGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
});

test('空取值被删除', () => {
  const headers = { 'Authentication-Info': 'qop=' };
  const result = guard.applyAuthenticationInfoGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
});

test('空头被删除', () => {
  const headers = { 'Authentication-Info': '   ' };
  const result = guard.applyAuthenticationInfoGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
});

test('多值被删除', () => {
  const headers = { 'Authentication-Info': [GOOD, 'qop=auth'] };
  const result = guard.applyAuthenticationInfoGuard(headers);
  assert.equal(result.reason, guard.REASON.MULTI_VALUE);
});

test('描述文本覆盖全部分支', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.equal(typeof guard.describeReason(reason), 'string');
  }
});
