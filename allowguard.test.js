'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./allowguard');

test('缺头不改动', () => {
  const r = guard.applyAllowGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('常规方法规范化', () => {
  const headers = { allow: 'get, head' };
  const r = guard.applyAllowGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers.allow, 'GET, HEAD');
});

test('通配符被拒', () => {
  const headers = { allow: '* , GET' };
  const r = guard.applyAllowGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.WILDCARD);
  assert.strictEqual(headers.allow, 'GET');
});

test('TRACE 被拒', () => {
  const headers = { allow: 'GET, TRACE' };
  const r = guard.applyAllowGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TRACE);
  assert.strictEqual(headers.allow, 'GET');
});

test('重复方法去重', () => {
  const headers = { allow: 'GET, get' };
  const r = guard.applyAllowGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.strictEqual(headers.allow, 'GET');
});

test('超长列表截断', () => {
  const names = Array.from({ length: 20 }, (_, i) => `X${i}`);
  const headers = { allow: names.join(', ') };
  const r = guard.applyAllowGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
  assert.strictEqual(headers.allow.split(',').length, 16);
});

test('空值删除', () => {
  const headers = { allow: '  ' };
  const r = guard.applyAllowGuard(headers);
  assert.strictEqual(headers.allow, undefined);
});
