'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./dntguard');

test('缺头不改动', () => {
  const r = guard.applyDntGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('DNT=1 保留', () => {
  const headers = { dnt: ['1'] };
  const r = guard.applyDntGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('DNT=0 保留', () => {
  const headers = { DNT: '0' };
  const r = guard.applyDntGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('非法 DNT 删除', () => {
  const headers = { dnt: 'true' };
  const r = guard.applyDntGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers.dnt, undefined);
});
