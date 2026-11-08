'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./xrequestidguard');

test('缺头不改动', () => {
  const r = guard.applyXRequestIdGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合规请求 ID 保留', () => {
  const headers = { 'x-request-id': ['req-20260101-abcd'] };
  const r = guard.applyXRequestIdGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('日志注入换行被删除', () => {
  const headers = { 'x-request-id': 'abc\nforged-entry' };
  const r = guard.applyXRequestIdGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.INJECTION);
  assert.strictEqual(headers['x-request-id'], undefined);
});

test('过长请求 ID 删除', () => {
  const headers = { 'x-request-id': 'a'.repeat(200) };
  const r = guard.applyXRequestIdGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
  assert.strictEqual(headers['x-request-id'], undefined);
});

test('非法字符删除', () => {
  const headers = { 'x-request-id': 'abc def ghi' };
  const r = guard.applyXRequestIdGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});
