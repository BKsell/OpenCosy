'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./trueclientipguard');

test('缺头不改动', () => {
  const r = guard.applyTrueClientIpGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('公网地址保留', () => {
  const headers = { 'true-client-ip': ['203.0.113.7'] };
  const r = guard.applyTrueClientIpGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('私网地址被删除', () => {
  const headers = { 'true-client-ip': '192.168.1.20' };
  const r = guard.applyTrueClientIpGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.PRIVATE);
  assert.strictEqual(headers['true-client-ip'], undefined);
});

test('多地址被删除', () => {
  const headers = { 'true-client-ip': '203.0.113.7, 198.51.100.9' };
  const r = guard.applyTrueClientIpGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
});

test('非法地址被删除', () => {
  const headers = { 'true-client-ip': 'not-an-ip' };
  const r = guard.applyTrueClientIpGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});
