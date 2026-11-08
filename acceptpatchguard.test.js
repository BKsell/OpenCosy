'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./acceptpatchguard');

function h(value) {
  return { 'accept-patch': [value] };
}

test('缺头返回 missing 且不改动', () => {
  const headers = {};
  const r = guard.applyAcceptPatchGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('允许的补丁类型不改动', () => {
  const headers = h('application/merge-patch+json');
  const r = guard.applyAcceptPatchGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('通配类型被剔除', () => {
  const headers = h('*/*, application/json-patch+json');
  const r = guard.applyAcceptPatchGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.WILDCARD);
  assert.strictEqual(headers['accept-patch'][0], 'application/json-patch+json');
});

test('HTML 类型被剔除', () => {
  const headers = h('text/html');
  const r = guard.applyAcceptPatchGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE_TYPE);
  assert.strictEqual(headers['accept-patch'], undefined);
});

test('脚本类型被剔除', () => {
  const headers = h('application/javascript, application/merge-patch+json');
  const r = guard.applyAcceptPatchGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE_TYPE);
  assert.strictEqual(headers['accept-patch'][0], 'application/merge-patch+json');
});

test('未知类型被剔除', () => {
  const headers = h('application/x-made-up');
  const r = guard.applyAcceptPatchGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.UNKNOWN_TYPE);
  assert.strictEqual(headers['accept-patch'], undefined);
});

test('重复类型去重', () => {
  const headers = h('text/plain, text/plain');
  const r = guard.applyAcceptPatchGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
  assert.strictEqual(headers['accept-patch'][0], 'text/plain');
});

test('参数被剥离但类型保留', () => {
  const headers = h('application/merge-patch+json; charset=utf-8');
  const r = guard.applyAcceptPatchGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('空值整头剥除', () => {
  const headers = h('  ');
  const r = guard.applyAcceptPatchGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers['accept-patch'], undefined);
});

test('超长取值整头剥除', () => {
  const headers = h(`text/plain, ${'x'.repeat(600)}`);
  const r = guard.applyAcceptPatchGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
  assert.strictEqual(headers['accept-patch'], undefined);
});

test('非数组取值被处理', () => {
  const headers = { 'Accept-Patch': 'application/merge-patch+json' };
  const r = guard.applyAcceptPatchGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('多类型混合只保留合规项', () => {
  const headers = h('application/xml, application/json-patch+json, text/plain');
  const r = guard.applyAcceptPatchGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE_TYPE);
  assert.strictEqual(headers['accept-patch'][0], 'application/json-patch+json, text/plain');
});

test('描述覆盖所有状态', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
