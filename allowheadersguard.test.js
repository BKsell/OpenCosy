'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./allowheadersguard');

test('缺头不改动', () => {
  const r = guard.applyAllowHeadersGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合规列表保持原样', () => {
  const headers = { 'access-control-allow-headers': 'content-type, x-request-id' };
  const r = guard.applyAllowHeadersGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('通配符被拒绝', () => {
  const headers = { 'access-control-allow-headers': '* , x-token' };
  const r = guard.applyAllowHeadersGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.WILDCARD);
  assert.strictEqual(headers['access-control-allow-headers'], 'x-token');
});

test('控制字符直接删除', () => {
  const headers = { 'access-control-allow-headers': 'x-a\u0000x-b' };
  const r = guard.applyAllowHeadersGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['access-control-allow-headers'], undefined);
});

test('超长列表截断', () => {
  const names = Array.from({ length: 30 }, (_, i) => `x-h${i}`);
  const headers = { 'access-control-allow-headers': names.join(', ') };
  const r = guard.applyAllowHeadersGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
  assert.strictEqual(headers['access-control-allow-headers'].split(',').length, 24);
});

test('重复项去重并小写', () => {
  const headers = { 'access-control-allow-headers': 'X-Token, x-token' };
  const r = guard.applyAllowHeadersGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
  assert.strictEqual(headers['access-control-allow-headers'], 'x-token');
});

test('非法项被剔除', () => {
  const headers = { 'access-control-allow-headers': 'x-token, bad header' };
  const r = guard.applyAllowHeadersGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['access-control-allow-headers'], 'x-token');
});

test('空值删除', () => {
  const headers = { 'access-control-allow-headers': '' };
  const r = guard.applyAllowHeadersGuard(headers);
  assert.strictEqual(headers['access-control-allow-headers'], undefined);
});
