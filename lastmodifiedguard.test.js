'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./lastmodifiedguard');

const NOW = Date.UTC(2026, 10, 7, 8, 0, 0);

function h(value) {
  return { 'Last-Modified': value };
}

test('合法日期不改动', () => {
  const headers = h(new Date(NOW - 86400000).toUTCString());
  const r = guard.applyLastModifiedGuard(headers, NOW);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('缺少头返回 missing', () => {
  const r = guard.applyLastModifiedGuard({}, NOW);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('无法解析被剥除', () => {
  const headers = h('yesterday');
  const r = guard.applyLastModifiedGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers['Last-Modified'], undefined);
});

test('空白值被剥除', () => {
  const headers = h('  ');
  const r = guard.applyLastModifiedGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers['Last-Modified'], undefined);
});

test('超长字段被剥除', () => {
  const headers = h(`${new Date(NOW).toUTCString()} ${'x'.repeat(40)}`);
  const r = guard.applyLastModifiedGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('未来日期被剥除', () => {
  const headers = h(new Date(NOW + 3600000).toUTCString());
  const r = guard.applyLastModifiedGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.FUTURE_DATE);
  assert.strictEqual(headers['Last-Modified'], undefined);
});

test('偏差预算内的未来日期放行', () => {
  const headers = h(new Date(NOW + 60000).toUTCString());
  const r = guard.applyLastModifiedGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('纪元前日期被剥除', () => {
  const headers = h('Thu, 01 Jan 1940 00:00:00 GMT');
  const r = guard.applyLastModifiedGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.PRE_EPOCH);
});

test('过旧日期被剥除', () => {
  const headers = h(new Date(NOW - guard.MAX_AGE_MS - 86400000).toUTCString());
  const r = guard.applyLastModifiedGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.TOO_OLD);
});

test('小写键名命中', () => {
  const headers = { 'last-modified': new Date(NOW - 86400000).toUTCString() };
  const r = guard.applyLastModifiedGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('数组取值取首项', () => {
  const headers = { 'Last-Modified': [new Date(NOW - 86400000).toUTCString(), 'bad'] };
  const r = guard.applyLastModifiedGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('describeReason 覆盖分支', () => {
  assert.match(guard.describeReason(guard.REASON.MALFORMED), /HTTP 日期/);
  assert.match(guard.describeReason(guard.REASON.FUTURE_DATE), /未来/);
  assert.match(guard.describeReason(guard.REASON.PRE_EPOCH), /纪元/);
  assert.match(guard.describeReason(guard.REASON.TOO_OLD), /陈旧/);
  assert.match(guard.describeReason(guard.REASON.OK), /通过/);
});
