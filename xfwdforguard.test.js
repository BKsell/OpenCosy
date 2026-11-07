'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./xfwdforguard');

test('缺头不改动', () => {
  const r = guard.applyXForwardedForGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('IPv4 合规', () => {
  const headers = { 'x-forwarded-for': '203.0.113.9' };
  const r = guard.applyXForwardedForGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('多跳 IPv4 合规', () => {
  const headers = { 'x-forwarded-for': '203.0.113.9, 198.51.100.7' };
  const r = guard.applyXForwardedForGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('unknown 被拒', () => {
  const headers = { 'x-forwarded-for': 'unknown' };
  const r = guard.applyXForwardedForGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.UNKNOWN_HOP);
  assert.strictEqual(headers['x-forwarded-for'], undefined);
});

test('非法地址被拒', () => {
  const headers = { 'x-forwarded-for': '999.1.1.1' };
  const r = guard.applyXForwardedForGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});

test('注入内容被拒', () => {
  const headers = { 'x-forwarded-for': '203.0.113.9, <script>' };
  const r = guard.applyXForwardedForGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});

test('多跳截断', () => {
  const hops = Array.from({ length: 20 }, () => '203.0.113.9');
  const headers = { 'x-forwarded-for': hops.join(', ') };
  const r = guard.applyXForwardedForGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
  assert.strictEqual(headers['x-forwarded-for'].split(',').length, 16);
});
