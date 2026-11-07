'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./contenttypeguard');

test('缺头不改动', () => {
  const r = guard.applyContentTypeGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('常规媒体类型合规', () => {
  const headers = { 'content-type': 'text/html; charset=utf-8' };
  const r = guard.applyContentTypeGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('空值表示无正文不改动', () => {
  const headers = { 'content-type': '' };
  const r = guard.applyContentTypeGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('缺少斜杠删除', () => {
  const headers = { 'content-type': 'texthtml' };
  const r = guard.applyContentTypeGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['content-type'], undefined);
});

test('未知参数删除', () => {
  const headers = { 'content-type': 'text/html; x-injected=evil' };
  const r = guard.applyContentTypeGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE_PARAM);
});

test('参数缺等号删除', () => {
  const headers = { 'content-type': 'text/html; charset' };
  const r = guard.applyContentTypeGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE_PARAM);
});

test('多值删除', () => {
  const headers = { 'content-type': ['text/html', 'text/plain'] };
  const r = guard.applyContentTypeGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
});

test('超长删除', () => {
  const headers = { 'content-type': `text/html; charset=utf-8; boundary=${'b'.repeat(200)}` };
  const r = guard.applyContentTypeGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});
