'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./secfetchuserguard');

test('缺头不改动', () => {
  const r = guard.applySecFetchUserGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('?1 合规', () => {
  const headers = { 'sec-fetch-user': '?1' };
  const r = guard.applySecFetchUserGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('?0 合规', () => {
  const headers = { 'sec-fetch-user': '?0' };
  const r = guard.applySecFetchUserGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('非布尔取值删除', () => {
  const headers = { 'sec-fetch-user': 'yes' };
  const r = guard.applySecFetchUserGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['sec-fetch-user'], undefined);
});

test('多值删除', () => {
  const headers = { 'sec-fetch-user': ['?1', '?0'] };
  const r = guard.applySecFetchUserGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
});

test('空值删除', () => {
  const headers = { 'sec-fetch-user': ' ' };
  const r = guard.applySecFetchUserGuard(headers);
  assert.strictEqual(headers['sec-fetch-user'], undefined);
});
