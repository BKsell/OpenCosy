'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./xrequestedwithguard');

test('缺头不改动', () => {
  const r = guard.applyXRequestedWithGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('标准取值合规', () => {
  const headers = { 'x-requested-with': 'XMLHttpRequest' };
  const r = guard.applyXRequestedWithGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('大小写归一', () => {
  const headers = { 'x-requested-with': 'xmlhttprequest' };
  const r = guard.applyXRequestedWithGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers['x-requested-with'], 'XMLHttpRequest');
});

test('异常取值删除', () => {
  const headers = { 'x-requested-with': 'com.evil.app' };
  const r = guard.applyXRequestedWithGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.UNEXPECTED);
  assert.strictEqual(headers['x-requested-with'], undefined);
});

test('多值删除', () => {
  const headers = { 'x-requested-with': ['XMLHttpRequest', 'XMLHttpRequest'] };
  const r = guard.applyXRequestedWithGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
});

test('空值删除', () => {
  const headers = { 'x-requested-with': ' ' };
  const r = guard.applyXRequestedWithGuard(headers);
  assert.strictEqual(headers['x-requested-with'], undefined);
});
