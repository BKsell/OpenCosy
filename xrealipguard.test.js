'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./xrealipguard');

test('缺头不改动', () => {
  const r = guard.applyXRealIpGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('IPv4 保留', () => {
  const headers = { 'x-real-ip': ['198.51.100.23'] };
  const r = guard.applyXRealIpGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('带端口 IPv4 保留', () => {
  const headers = { 'x-real-ip': '198.51.100.23:443' };
  const r = guard.applyXRealIpGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('越界端口被删除', () => {
  const headers = { 'x-real-ip': '198.51.100.23:70000' };
  const r = guard.applyXRealIpGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_PORT);
});

test('多地址被删除', () => {
  const headers = { 'x-real-ip': '198.51.100.23, 10.0.0.1' };
  const r = guard.applyXRealIpGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
});

test('越界八位组被删除', () => {
  const headers = { 'x-real-ip': '999.1.1.1' };
  const r = guard.applyXRealIpGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});
