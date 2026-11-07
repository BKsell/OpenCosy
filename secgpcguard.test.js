'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./secgpcguard');

test('缺头不改动', () => {
  const r = guard.applySecGpcGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合法 GPC 信号保留', () => {
  const headers = { 'sec-gpc': ['1'] };
  const r = guard.applySecGpcGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(headers['sec-gpc'][0], '1');
});

test('非法 GPC 信号删除', () => {
  const headers = { 'sec-gpc': 'yes' };
  const r = guard.applySecGpcGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['sec-gpc'], undefined);
});
