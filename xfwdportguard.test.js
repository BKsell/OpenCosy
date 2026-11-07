'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./xfwdportguard');

test('缺头不改动', () => {
  const r = guard.applyXForwardedPortGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合法端口合规', () => {
  const headers = { 'x-forwarded-port': '443' };
  const r = guard.applyXForwardedPortGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('多跳合规', () => {
  const headers = { 'x-forwarded-port': '443, 8443' };
  const r = guard.applyXForwardedPortGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('越界端口删除', () => {
  const headers = { 'x-forwarded-port': '70000' };
  const r = guard.applyXForwardedPortGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['x-forwarded-port'], undefined);
});

test('非数字删除', () => {
  const headers = { 'x-forwarded-port': 'https' };
  const r = guard.applyXForwardedPortGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});

test('多跳截断', () => {
  const headers = { 'x-forwarded-port': '443, 443, 443, 443, 443' };
  const r = guard.applyXForwardedPortGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
  assert.strictEqual(headers['x-forwarded-port'].split(',').length, 4);
});

test('空值删除', () => {
  const headers = { 'x-forwarded-port': ' ' };
  const r = guard.applyXForwardedPortGuard(headers);
  assert.strictEqual(headers['x-forwarded-port'], undefined);
});
