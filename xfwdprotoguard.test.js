'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./xfwdprotoguard');

test('缺头不改动', () => {
  const r = guard.applyXForwardedProtoGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('https 合规', () => {
  const headers = { 'x-forwarded-proto': 'https' };
  const r = guard.applyXForwardedProtoGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('多跳值合规', () => {
  const headers = { 'x-forwarded-proto': 'https, http' };
  const r = guard.applyXForwardedProtoGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('未知协议删除', () => {
  const headers = { 'x-forwarded-proto': 'ftp' };
  const r = guard.applyXForwardedProtoGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE);
  assert.strictEqual(headers['x-forwarded-proto'], undefined);
});

test('控制字符删除', () => {
  const headers = { 'x-forwarded-proto': 'https\u0000' };
  const r = guard.applyXForwardedProtoGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});

test('多跳截断', () => {
  const headers = { 'x-forwarded-proto': 'https, http, https, http, https' };
  const r = guard.applyXForwardedProtoGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
  assert.strictEqual(headers['x-forwarded-proto'].split(',').length, 4);
});

test('空值删除', () => {
  const headers = { 'x-forwarded-proto': ' ' };
  const r = guard.applyXForwardedProtoGuard(headers);
  assert.strictEqual(headers['x-forwarded-proto'], undefined);
});
