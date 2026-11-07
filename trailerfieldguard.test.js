'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./trailerfieldguard');

function h(value) {
  return { trailer: [value] };
}

test('缺头返回 missing', () => {
  const r = guard.applyTrailerFieldGuard({});
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('普通字段声明不改动', () => {
  const headers = h('X-Checksum, X-Request-Id');
  const r = guard.applyTrailerFieldGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('禁止字段被剥除', () => {
  const headers = h('Set-Cookie, X-Checksum');
  const r = guard.applyTrailerFieldGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.FORBIDDEN_NAME);
  assert.strictEqual(headers.trailer[0], 'x-checksum');
});

test('content-length 声明被剥除', () => {
  const r = guard.inspectTrailer('Content-Length');
  assert.strictEqual(r.reason, guard.REASON.FORBIDDEN_NAME);
  assert.strictEqual(r.fields.length, 0);
});

test('authorization 声明被剥除', () => {
  const r = guard.inspectTrailer('Authorization, X-Trace');
  assert.strictEqual(r.reason, guard.REASON.FORBIDDEN_NAME);
  assert.deepStrictEqual(r.fields, ['x-trace']);
});

test('非法字段名被剥除', () => {
  const r = guard.inspectTrailer('bad field, X-Ok');
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.deepStrictEqual(r.fields, ['x-ok']);
});

test('重复字段去重', () => {
  const headers = h('X-Trace, X-Trace');
  const r = guard.applyTrailerFieldGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
  assert.strictEqual(headers.trailer[0], 'x-trace');
});

test('字段过多被截断', () => {
  const names = [];
  for (let i = 0; i < 20; i += 1) names.push(`X-Field-${i}`);
  const headers = h(names.join(', '));
  const r = guard.applyTrailerFieldGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
  assert.strictEqual(headers.trailer[0].split(', ').length, 16);
});

test('超长声明整体剥除', () => {
  const headers = h(`X-${'a'.repeat(600)}`);
  const r = guard.applyTrailerFieldGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
  assert.strictEqual(headers.trailer, undefined);
});

test('全为禁止字段时删头', () => {
  const headers = h('Set-Cookie, Host');
  const r = guard.applyTrailerFieldGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.FORBIDDEN_NAME);
  assert.strictEqual(headers.trailer, undefined);
});

test('describeReason 覆盖主要状态', () => {
  assert.strictEqual(typeof guard.describeReason(guard.REASON.OK), 'string');
  assert.strictEqual(typeof guard.describeReason('unknown'), 'string');
});
