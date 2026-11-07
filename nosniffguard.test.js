'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./nosniffguard');

test('缺头不改动', () => {
  const r = guard.applyNoSniffGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('nosniff 合规', () => {
  const headers = { 'x-content-type-options': ['nosniff'] };
  const r = guard.applyNoSniffGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('非法取值收敛', () => {
  const headers = { 'x-content-type-options': 'sniff' };
  const r = guard.applyNoSniffGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['x-content-type-options'], 'nosniff');
});

test('重复取值收敛', () => {
  const headers = { 'x-content-type-options': 'nosniff, nosniff' };
  const r = guard.applyNoSniffGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
});

test('空值收敛', () => {
  const headers = { 'x-content-type-options': '' };
  const r = guard.applyNoSniffGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers['x-content-type-options'], 'nosniff');
});
