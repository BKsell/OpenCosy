'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./chmobileguard');

test('缺头不改动', () => {
  const r = guard.applyChMobileGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('?1 合规', () => {
  const headers = { 'sec-ch-ua-mobile': '?1' };
  const r = guard.applyChMobileGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('非法取值收敛为 ?0', () => {
  const headers = { 'sec-ch-ua-mobile': 'true' };
  const r = guard.applyChMobileGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['sec-ch-ua-mobile'], '?0');
});

test('多值删除', () => {
  const headers = { 'sec-ch-ua-mobile': ['?0', '?1'] };
  const r = guard.applyChMobileGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
  assert.strictEqual(headers['sec-ch-ua-mobile'], undefined);
});

test('空值删除', () => {
  const headers = { 'sec-ch-ua-mobile': '' };
  const r = guard.applyChMobileGuard(headers);
  assert.strictEqual(headers['sec-ch-ua-mobile'], undefined);
});
