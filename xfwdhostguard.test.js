'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./xfwdhostguard');

test('缺头不改动', () => {
  const r = guard.applyXForwardedHostGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('主机名合规', () => {
  const headers = { 'x-forwarded-host': 'example.com' };
  const r = guard.applyXForwardedHostGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('带端口合规', () => {
  const headers = { 'x-forwarded-host': 'example.com:8443' };
  const r = guard.applyXForwardedHostGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('端口越界删除', () => {
  const headers = { 'x-forwarded-host': 'example.com:70000' };
  const r = guard.applyXForwardedHostGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});

test('换行注入删除', () => {
  const headers = { 'x-forwarded-host': 'example.com\r\nX-Evil: 1' };
  const r = guard.applyXForwardedHostGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['x-forwarded-host'], undefined);
});

test('多跳截断', () => {
  const headers = { 'x-forwarded-host': 'a.com, b.com, c.com, d.com, e.com' };
  const r = guard.applyXForwardedHostGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
  assert.strictEqual(headers['x-forwarded-host'].split(',').length, 4);
});

test('带空格主机删除', () => {
  const headers = { 'x-forwarded-host': 'exa mple.com' };
  const r = guard.applyXForwardedHostGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});
