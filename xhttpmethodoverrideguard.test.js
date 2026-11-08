'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./xhttpmethodoverrideguard');

test('缺头不改动', () => {
  const r = guard.applyXHttpMethodOverrideGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('PATCH 合规', () => {
  const headers = { 'x-http-method-override': 'PATCH' };
  const r = guard.applyXHttpMethodOverrideGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('小写规范化为大写', () => {
  const headers = { 'x-http-method-override': 'delete' };
  const r = guard.applyXHttpMethodOverrideGuard(headers);
  assert.strictEqual(headers['x-http-method-override'], 'DELETE');
});

test('GET 不被允许', () => {
  const headers = { 'x-http-method-override': 'GET' };
  const r = guard.applyXHttpMethodOverrideGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE_METHOD);
  assert.strictEqual(headers['x-http-method-override'], undefined);
});

test('CONNECT 被拒', () => {
  const headers = { 'x-http-method-override': 'CONNECT' };
  const r = guard.applyXHttpMethodOverrideGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE_METHOD);
});

test('注入字符被拒', () => {
  const headers = { 'x-http-method-override': 'PUT\r\nX-Evil: 1' };
  const r = guard.applyXHttpMethodOverrideGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});

test('多值删除', () => {
  const headers = { 'x-http-method-override': ['PUT', 'DELETE'] };
  const r = guard.applyXHttpMethodOverrideGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
});

test('超长删除', () => {
  const headers = { 'x-http-method-override': 'PATCHPATCHPATCHPATCHPATCH' };
  const r = guard.applyXHttpMethodOverrideGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_LONG);
});
