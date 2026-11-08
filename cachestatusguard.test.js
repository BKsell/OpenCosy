'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./cachestatusguard');

function h(value) {
  return { 'cache-status': [value] };
}

test('缺头返回 missing', () => {
  const r = guard.applyCacheStatusGuard({});
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合规缓存状态不改动', () => {
  const headers = h('OriginCache; hit; ttl=3600');
  const r = guard.applyCacheStatusGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('多成员合规不改动', () => {
  const headers = h('Edge; hit; ttl=60, OriginCache; hit');
  const r = guard.applyCacheStatusGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('带主机名的缓存标识被剥除', () => {
  const headers = h('cdn-node-01.internal.example.com; hit');
  const r = guard.applyCacheStatusGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.SUSPICIOUS_NAME);
  assert.strictEqual(headers['cache-status'], undefined);
});

test('含斜杠的缓存标识被剥除', () => {
  const headers = h('edge/poP1; hit');
  const r = guard.applyCacheStatusGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.SUSPICIOUS_NAME);
});

test('key 参数被剥离但保留成员', () => {
  const headers = h('Edge; hit; key=https://user@example.com/path');
  const r = guard.applyCacheStatusGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.SENSITIVE_PARAM);
  assert.strictEqual(headers['cache-status'][0], 'Edge; hit');
});

test('detail 参数被剥离', () => {
  const headers = h('Edge; hit; detail=requestid-42');
  const r = guard.applyCacheStatusGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.SENSITIVE_PARAM);
  assert.ok(!String(headers['cache-status'][0]).includes('detail'));
});

test('转发跳数过长时剥除 fwd', () => {
  const headers = h('Edge; fwd=9; hit');
  const r = guard.applyCacheStatusGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.FORWARD_CHAIN);
  assert.strictEqual(headers['cache-status'][0], 'Edge; hit');
});

test('合法转发跳数保留', () => {
  const headers = h('Edge; fwd=2; hit');
  const r = guard.applyCacheStatusGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('非法 fwd-status 被剥离', () => {
  const headers = h('Edge; fwd-status=42');
  const r = guard.applyCacheStatusGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers['cache-status'][0], 'Edge');
});

test('非法 ttl 被剥离', () => {
  const headers = h('Edge; ttl=abc');
  const r = guard.applyCacheStatusGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('成员过多被截断', () => {
  const members = [];
  for (let i = 0; i < 12; i += 1) {
    members.push(`Cache${i}; hit`);
  }
  const headers = h(members.join(', '));
  const r = guard.applyCacheStatusGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
  assert.strictEqual(headers['cache-status'][0].split(', ').length, 8);
});

test('超长取值整体剥除', () => {
  const headers = h(`${'Edge; hit, '.repeat(120)}tail`);
  const r = guard.applyCacheStatusGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
  assert.strictEqual(headers['cache-status'], undefined);
});

test('空取值视为非法', () => {
  const headers = h('  ');
  const r = guard.applyCacheStatusGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('describeReason 覆盖主要状态', () => {
  assert.strictEqual(typeof guard.describeReason(guard.REASON.OK), 'string');
  assert.strictEqual(typeof guard.describeReason('unknown'), 'string');
});
