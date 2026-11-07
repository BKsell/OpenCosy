'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./maxageguard');

test('缺头不改动', () => {
  const r = guard.applyMaxAgeGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合规值不改动', () => {
  const headers = { 'access-control-max-age': '600' };
  const r = guard.applyMaxAgeGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('非数字回落到默认值', () => {
  const headers = { 'access-control-max-age': 'ten minutes' };
  const r = guard.applyMaxAgeGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['access-control-max-age'], '600');
});

test('负值收敛为 0', () => {
  const headers = { 'access-control-max-age': '-30' };
  const r = guard.applyMaxAgeGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.NEGATIVE);
  assert.strictEqual(headers['access-control-max-age'], '0');
});

test('超大值收敛到上限', () => {
  const headers = { 'access-control-max-age': '2592000' };
  const r = guard.applyMaxAgeGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_LARGE);
  assert.strictEqual(headers['access-control-max-age'], '86400');
});

test('多值视为异常', () => {
  const headers = { 'access-control-max-age': ['60', '120'] };
  const r = guard.applyMaxAgeGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers['access-control-max-age'], '600');
});

test('空值删除', () => {
  const headers = { 'access-control-max-age': '' };
  const r = guard.applyMaxAgeGuard(headers);
  assert.strictEqual(headers['access-control-max-age'], undefined);
});

test('大小写键名可识别', () => {
  const headers = { 'Access-Control-Max-Age': '120' };
  const r = guard.applyMaxAgeGuard(headers);
  assert.strictEqual(r.changed, false);
});
