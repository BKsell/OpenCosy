'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./connectionguard');

function h(value) {
  return { connection: [value] };
}

test('缺头不改动', () => {
  const r = guard.applyConnectionGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('keep-alive 合规', () => {
  const headers = h('keep-alive');
  const r = guard.applyConnectionGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('受保护头被剔除', () => {
  const headers = h('keep-alive, host');
  const r = guard.applyConnectionGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.HOP_BY_HOP_LEAK);
  assert.strictEqual(headers.connection, 'keep-alive');
});

test('非法令牌被剔除', () => {
  const headers = h('keep-alive, bad token');
  const r = guard.applyConnectionGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_TOKEN);
  assert.strictEqual(headers.connection, 'keep-alive');
});

test('全非法时删除', () => {
  const headers = h('bad token');
  const r = guard.applyConnectionGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers.connection, undefined);
});
