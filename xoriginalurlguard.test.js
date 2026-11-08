'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./xoriginalurlguard');

test('缺头不改动', () => {
  const r = guard.applyXOriginalUrlGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('相对路径合规', () => {
  const headers = { 'x-original-url': '/app/index.html?v=1' };
  const r = guard.applyXOriginalUrlGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('绝对 URL 被拒', () => {
  const headers = { 'x-original-url': 'https://evil.example/app' };
  const r = guard.applyXOriginalUrlGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.ABSOLUTE_URL);
  assert.strictEqual(headers['x-original-url'], undefined);
});

test('协议相对 URL 被拒', () => {
  const headers = { 'x-original-url': '//evil.example/app' };
  const r = guard.applyXOriginalUrlGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.ABSOLUTE_URL);
});

test('路径穿越被拒', () => {
  const headers = { 'x-original-url': '/../../etc/passwd' };
  const r = guard.applyXOriginalUrlGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TRAVERSAL);
});

test('规范化后的穿越被拒', () => {
  const headers = { 'x-original-url': '/app/../../../secret' };
  const r = guard.applyXOriginalUrlGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TRAVERSAL);
});

test('反斜杠被拒', () => {
  const headers = { 'x-original-url': '/app\\..\\secret' };
  const r = guard.applyXOriginalUrlGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TRAVERSAL);
});

test('换行注入被拒', () => {
  const headers = { 'x-original-url': '/app\r\nX-Evil: 1' };
  const r = guard.applyXOriginalUrlGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});

test('多值删除', () => {
  const headers = { 'x-original-url': ['/a', '/b'] };
  const r = guard.applyXOriginalUrlGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
});
