'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./secfetchmodeguard');

test('缺头不改动', () => {
  const r = guard.applySecFetchModeGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('navigate 合规', () => {
  const headers = { 'sec-fetch-mode': 'navigate' };
  const r = guard.applySecFetchModeGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('未知取值删除', () => {
  const headers = { 'sec-fetch-mode': 'teleport' };
  const r = guard.applySecFetchModeGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE);
  assert.strictEqual(headers['sec-fetch-mode'], undefined);
});

test('多值删除', () => {
  const headers = { 'sec-fetch-mode': ['cors', 'navigate'] };
  const r = guard.applySecFetchModeGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
  assert.strictEqual(headers['sec-fetch-mode'], undefined);
});

test('空值删除', () => {
  const headers = { 'sec-fetch-mode': '  ' };
  const r = guard.applySecFetchModeGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});

test('大小写归一', () => {
  const headers = { 'sec-fetch-mode': 'CORS' };
  const r = guard.applySecFetchModeGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers['sec-fetch-mode'], 'cors');
});
