'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./teguard');

function h(value) {
  return { te: [value] };
}

test('缺头不改动', () => {
  const r = guard.applyTeGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('trailers 合规', () => {
  const headers = h('trailers');
  const r = guard.applyTeGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('未知编码被剔除', () => {
  const headers = h('gzip, br');
  const r = guard.applyTeGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.UNSUPPORTED);
  assert.strictEqual(headers.te, 'gzip');
});

test('全部不支持时删除', () => {
  const headers = h('br');
  const r = guard.applyTeGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers.te, undefined);
});
