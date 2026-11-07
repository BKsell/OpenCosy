'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./ifunmodifiedsinceguard');

test('缺头不改动', () => {
  const r = guard.applyIfUnmodifiedSinceGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('标准日期合规', () => {
  const headers = { 'if-unmodified-since': 'Wed, 21 Oct 2026 07:28:00 GMT' };
  const r = guard.applyIfUnmodifiedSinceGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('非法月份删除', () => {
  const headers = { 'if-unmodified-since': 'Wed, 21 Foo 2026 07:28:00 GMT' };
  const r = guard.applyIfUnmodifiedSinceGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});

test('缺时区删除', () => {
  const headers = { 'if-unmodified-since': 'Wed, 21 Oct 2026 07:28:00' };
  const r = guard.applyIfUnmodifiedSinceGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});

test('多值删除', () => {
  const headers = { 'if-unmodified-since': ['Wed, 21 Oct 2026 07:28:00 GMT', 'Wed, 21 Oct 2026 07:28:00 GMT'] };
  const r = guard.applyIfUnmodifiedSinceGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
});

test('超长删除', () => {
  const headers = { 'if-unmodified-since': `Wed, 21 Oct 2026 07:28:00 GMT${'x'.repeat(20)}` };
  const r = guard.applyIfUnmodifiedSinceGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_LONG);
});

test('空值删除', () => {
  const headers = { 'if-unmodified-since': ' ' };
  const r = guard.applyIfUnmodifiedSinceGuard(headers);
  assert.strictEqual(headers['if-unmodified-since'], undefined);
});
