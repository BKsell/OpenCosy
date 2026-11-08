'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./viaguard');

function h(value) {
  return { via: [value] };
}

test('缺头不改动', () => {
  const r = guard.applyViaGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合规代理链不改动', () => {
  const headers = h('1.1 proxy.example.com, 1.0 edge.example.net');
  const r = guard.applyViaGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('内部主机暴露被剔除', () => {
  const headers = h('1.1 internal-gateway');
  const r = guard.applyViaGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.SPOOFED);
  assert.strictEqual(headers.via, undefined);
});

test('非法条目不保留', () => {
  const headers = h('@@@');
  const r = guard.applyViaGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.SPOOFED);
});

test('超长头删除', () => {
  const headers = h('1.1 a,'.repeat(200));
  const r = guard.applyViaGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
  assert.strictEqual(headers.via, undefined);
});
