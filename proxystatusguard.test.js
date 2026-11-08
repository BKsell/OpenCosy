'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./proxystatusguard');

function h(value) {
  return { 'proxy-status': [value] };
}

test('缺头返回 missing 且不改动', () => {
  const headers = {};
  const r = guard.applyProxyStatusGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合规代理状态不改动', () => {
  const headers = h('cdn-edge; proto=http');
  const r = guard.applyProxyStatusGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('details 参数被剔除', () => {
  const headers = h('cdn-edge; error=timeout; details="upstream 10.0.0.7 timed out"');
  const r = guard.applyProxyStatusGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.DETAILS_LEAK);
  assert.strictEqual(headers['proxy-status'][0], 'cdn-edge; error=timeout');
});

test('next-hop-ip 被剔除', () => {
  const headers = h('gw; next-hop-ip=192.168.1.4');
  const r = guard.applyProxyStatusGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.DETAILS_LEAK);
  assert.strictEqual(headers['proxy-status'][0], 'gw');
});

test('内部地址形态代理标识被剔除', () => {
  const headers = h('10.0.0.7:8080; error=timeout');
  const r = guard.applyProxyStatusGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.INTERNAL_AGENT);
});

test('带路径的代理标识被剔除', () => {
  const headers = h('/internal/proxy-7');
  const r = guard.applyProxyStatusGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.INTERNAL_AGENT);
});

test('内嵌凭据被剔除', () => {
  const headers = h('user:pw@edge');
  const r = guard.applyProxyStatusGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.CREDENTIALS);
});

test('空值整头剥除', () => {
  const headers = h('  ');
  const r = guard.applyProxyStatusGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers['proxy-status'], undefined);
});

test('超长取值整头剥除', () => {
  const headers = h(`edge; error=timeout; x=${'y'.repeat(1100)}`);
  const r = guard.applyProxyStatusGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});

test('多条状态只保留合规项', () => {
  const headers = h('edge-a; proto=http, 172.16.0.1; error=refused');
  const r = guard.applyProxyStatusGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.INTERNAL_AGENT);
  assert.strictEqual(headers['proxy-status'][0], 'edge-a; proto=http');
});

test('引号内的分号不被切分', () => {
  const headers = h('edge; details="a;b"; error=timeout');
  const r = guard.applyProxyStatusGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers['proxy-status'][0], 'edge; error=timeout');
});

test('重复条目被去重', () => {
  const headers = h('edge; proto=http, edge; proto=http');
  const r = guard.applyProxyStatusGuard(headers);
  assert.strictEqual(headers['proxy-status'][0], 'edge; proto=http');
});

test('描述覆盖所有状态', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
