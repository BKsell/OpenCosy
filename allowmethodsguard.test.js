'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./allowmethodsguard');

test('缺头不改动', () => {
  const r = guard.applyAllowMethodsGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('常规方法规范化为大写', () => {
  const headers = { 'access-control-allow-methods': 'GET, post, OPTIONS' };
  const r = guard.applyAllowMethodsGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers['access-control-allow-methods'], 'GET, POST, OPTIONS');
});

test('通配符被拒绝', () => {
  const headers = { 'access-control-allow-methods': '* , GET' };
  const r = guard.applyAllowMethodsGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.WILDCARD);
  assert.strictEqual(headers['access-control-allow-methods'], 'GET');
});

test('带凭据时拒绝 TRACE', () => {
  const headers = { 'access-control-allow-methods': 'GET, TRACE' };
  const r = guard.applyAllowMethodsGuard(headers, { credentials: true });
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['access-control-allow-methods'], 'GET');
});

test('重复方法去重', () => {
  const headers = { 'access-control-allow-methods': 'GET, get' };
  const r = guard.applyAllowMethodsGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
  assert.strictEqual(headers['access-control-allow-methods'], 'GET');
});

test('方法名规范化为大写', () => {
  const headers = { 'access-control-allow-methods': 'post' };
  const r = guard.applyAllowMethodsGuard(headers);
  assert.strictEqual(headers['access-control-allow-methods'], 'POST');
});

test('非法方法被剔除', () => {
  const headers = { 'access-control-allow-methods': 'GET, GE T' };
  const r = guard.applyAllowMethodsGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});

test('全部非法时回落到默认值', () => {
  const headers = { 'access-control-allow-methods': '* , GE T' };
  const r = guard.applyAllowMethodsGuard(headers);
  assert.strictEqual(headers['access-control-allow-methods'], 'GET, HEAD, POST, OPTIONS');
});
