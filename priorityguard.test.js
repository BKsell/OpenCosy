'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./priorityguard');

function h(value) {
  return { priority: [value] };
}

test('缺头返回 missing 且不改动', () => {
  const headers = {};
  const r = guard.applyPriorityGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合规紧急度不改动', () => {
  const headers = h('u=3, i');
  const r = guard.applyPriorityGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('紧急度越界被剔除', () => {
  const headers = h('u=9, i=1');
  const r = guard.applyPriorityGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_URGENCY);
  assert.strictEqual(headers.priority[0], 'i=1');
});

test('紧急度非整数被剔除', () => {
  const headers = h('u=high');
  const r = guard.applyPriorityGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_URGENCY);
  assert.strictEqual(headers.priority, undefined);
});

test('未知键被剔除', () => {
  const headers = h('u=2, x-secret=1');
  const r = guard.applyPriorityGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.UNKNOWN_KEY);
  assert.strictEqual(headers.priority[0], 'u=2');
});

test('增量标记非法被剔除', () => {
  const headers = h('i=2, u=5');
  const r = guard.applyPriorityGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_INCREMENTAL);
  assert.strictEqual(headers.priority[0], 'u=5');
});

test('重复键去重', () => {
  const headers = h('u=1, u=2');
  const r = guard.applyPriorityGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE_KEY);
  assert.strictEqual(headers.priority[0], 'u=1');
});

test('空值整头剥除', () => {
  const headers = h('   ');
  const r = guard.applyPriorityGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers.priority, undefined);
});

test('超长取值整头剥除', () => {
  const headers = h(`u=1, ${'a'.repeat(600)}`);
  const r = guard.applyPriorityGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
  assert.strictEqual(headers.priority, undefined);
});

test('保留原有头键大小写', () => {
  const headers = { Priority: ['U=4'] };
  const r = guard.applyPriorityGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.ok(Array.isArray(headers.Priority));
});

test('带参数的增量键保留', () => {
  const headers = h('u=6; foo=bar, i');
  const r = guard.applyPriorityGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('描述覆盖所有状态', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
