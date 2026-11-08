'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./expiresguard');

test('缺头不改动', () => {
  const r = guard.applyExpiresGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('标准日期合规', () => {
  const headers = { expires: 'Wed, 21 Oct 2026 07:28:00 GMT' };
  const r = guard.applyExpiresGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('字面 0 收敛为过去时间', () => {
  const headers = { expires: '0' };
  const r = guard.applyExpiresGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers.expires, 'Thu, 01 Jan 1970 00:00:00 GMT');
});

test('非法日期收敛为过去时间', () => {
  const headers = { expires: 'tomorrow' };
  const r = guard.applyExpiresGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers.expires, 'Thu, 01 Jan 1970 00:00:00 GMT');
});

test('多值收敛为过去时间', () => {
  const headers = { expires: ['Wed, 21 Oct 2026 07:28:00 GMT', 'Wed, 21 Oct 2026 07:28:00 GMT'] };
  const r = guard.applyExpiresGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
});

test('空值删除', () => {
  const headers = { expires: '' };
  const r = guard.applyExpiresGuard(headers);
  assert.strictEqual(headers.expires, undefined);
});

test('非标准时区被拒', () => {
  const headers = { expires: 'Wed, 21 Oct 2026 07:28:00 +0800' };
  const r = guard.applyExpiresGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});
