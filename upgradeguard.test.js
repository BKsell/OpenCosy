'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./upgradeguard');

function h(value, connection) {
  const headers = { upgrade: [value] };
  if (connection) headers.connection = [connection];
  return headers;
}

test('缺头返回 missing 且不改动', () => {
  const headers = {};
  const r = guard.applyUpgradeHeaderGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('websocket 配对连接头保留', () => {
  const headers = h('websocket', 'keep-alive, Upgrade');
  const r = guard.applyUpgradeHeaderGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('h2c 被剔除', () => {
  const headers = h('h2c', 'Upgrade');
  const r = guard.applyUpgradeHeaderGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.INSECURE_PROTOCOL);
  assert.strictEqual(headers.upgrade, undefined);
});

test('HTTP/1.0 被剔除', () => {
  const headers = h('HTTP/1.0', 'Upgrade');
  const r = guard.applyUpgradeHeaderGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.INSECURE_PROTOCOL);
});

test('未知协议被剔除', () => {
  const headers = h('x-custom-proto', 'Upgrade');
  const r = guard.applyUpgradeHeaderGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.UNKNOWN_PROTOCOL);
});

test('无 connection: upgrade 时整头剥除', () => {
  const headers = h('websocket', 'keep-alive');
  const r = guard.applyUpgradeHeaderGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.WITHOUT_CONNECTION);
  assert.strictEqual(headers.upgrade, undefined);
});

test('无 connection 头时整头剥除', () => {
  const headers = h('websocket');
  const r = guard.applyUpgradeHeaderGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.WITHOUT_CONNECTION);
});

test('混合协议只保留 websocket', () => {
  const headers = h('h2c, websocket', 'Upgrade');
  const r = guard.applyUpgradeHeaderGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers.upgrade[0], 'websocket');
});

test('空值整头剥除', () => {
  const headers = h('   ', 'Upgrade');
  const r = guard.applyUpgradeHeaderGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('超长取值整头剥除', () => {
  const headers = h('websocket, ' + 'a'.repeat(300), 'Upgrade');
  const r = guard.applyUpgradeHeaderGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});

test('重复协议去重', () => {
  const headers = h('websocket, websocket', 'Upgrade');
  const r = guard.applyUpgradeHeaderGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('描述覆盖所有状态', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
