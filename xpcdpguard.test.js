'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./xpcdpguard');

test('缺头不改动', () => {
  const r = guard.applyXpcdpGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('none 合规', () => {
  const headers = { 'x-permitted-cross-domain-policies': 'none' };
  const r = guard.applyXpcdpGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('master-only 合规', () => {
  const headers = { 'x-permitted-cross-domain-policies': ['master-only'] };
  const r = guard.applyXpcdpGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('未知取值收敛为 none', () => {
  const headers = { 'x-permitted-cross-domain-policies': 'by-header' };
  const r = guard.applyXpcdpGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['x-permitted-cross-domain-policies'], 'none');
});

test('重复取值收敛为 none', () => {
  const headers = { 'x-permitted-cross-domain-policies': 'none, all' };
  const r = guard.applyXpcdpGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers['x-permitted-cross-domain-policies'], 'none');
});
