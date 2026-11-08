'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./ifmodifiedsinceguard');

test('缺头不改动', () => {
  const r = guard.applyIfModifiedSinceGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('标准日期合规', () => {
  const headers = { 'if-modified-since': 'Wed, 21 Oct 2026 07:28:00 GMT' };
  const r = guard.applyIfModifiedSinceGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('ISO 日期删除', () => {
  const headers = { 'if-modified-since': '2026-10-21T07:28:00Z' };
  const r = guard.applyIfModifiedSinceGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['if-modified-since'], undefined);
});

test('列表按超长删除', () => {
  const headers = { 'if-modified-since': 'Wed, 21 Oct 2026 07:28:00 GMT, Thu, 22 Oct 2026 07:28:00 GMT' };
  const r = guard.applyIfModifiedSinceGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_LONG);
  assert.strictEqual(headers['if-modified-since'], undefined);
});

test('多值删除', () => {
  const headers = { 'if-modified-since': ['Wed, 21 Oct 2026 07:28:00 GMT', 'Wed, 21 Oct 2026 07:28:00 GMT'] };
  const r = guard.applyIfModifiedSinceGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
});

test('超长删除', () => {
  const headers = { 'if-modified-since': `Wed, 21 Oct 2026 07:28:00 GMT${'x'.repeat(20)}` };
  const r = guard.applyIfModifiedSinceGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_LONG);
});

test('空值删除', () => {
  const headers = { 'if-modified-since': '' };
  const r = guard.applyIfModifiedSinceGuard(headers);
  assert.strictEqual(headers['if-modified-since'], undefined);
});
