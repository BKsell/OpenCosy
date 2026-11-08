'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./exposeheadersguard');

test('缺头不改动', () => {
  const r = guard.applyExposeHeadersGuard({});
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合法列表保持原样', () => {
  const headers = { 'access-control-expose-headers': 'X-Request-Id, Content-Length' };
  const r = guard.applyExposeHeadersGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('带凭据时拒绝通配符', () => {
  const headers = { 'access-control-expose-headers': '* , X-Trace' };
  const r = guard.applyExposeHeadersGuard(headers, { credentials: true });
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.WILDCARD);
  assert.strictEqual(headers['access-control-expose-headers'], 'X-Trace');
});

test('无凭据允许通配符', () => {
  const headers = { 'access-control-expose-headers': '*' };
  const r = guard.applyExposeHeadersGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('非法字符被剔除', () => {
  const headers = { 'access-control-expose-headers': 'X-Ok, X-Bad Header, X-Slash/Value' };
  const r = guard.applyExposeHeadersGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['access-control-expose-headers'], 'X-Ok');
});

test('重复项去重', () => {
  const headers = { 'access-control-expose-headers': 'X-A, x-a' };
  const r = guard.applyExposeHeadersGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
  assert.strictEqual(headers['access-control-expose-headers'], 'X-A');
});

test('超长列表截断', () => {
  const names = Array.from({ length: 40 }, (_, i) => `X-H${i}`);
  const headers = { 'access-control-expose-headers': names.join(', ') };
  const r = guard.applyExposeHeadersGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
  assert.strictEqual(headers['access-control-expose-headers'].split(',').length, 32);
});

test('空值删除', () => {
  const headers = { 'access-control-expose-headers': '   ' };
  const r = guard.applyExposeHeadersGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers['access-control-expose-headers'], undefined);
});
