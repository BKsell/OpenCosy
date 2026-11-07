'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./savedataguard');

test('缺头不改动', () => {
  const r = guard.applySaveDataGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('Save-Data: on 保留', () => {
  const headers = { 'save-data': ['on'] };
  const r = guard.applySaveDataGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('非法取值删除', () => {
  const headers = { 'save-data': 'off' };
  const r = guard.applySaveDataGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['save-data'], undefined);
});

test('重复取值删除', () => {
  const headers = { 'save-data': ['on', 'on'] };
  const r = guard.applySaveDataGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers['save-data'], undefined);
});
