'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./taoguard');

test('缺头不改动', () => {
  const r = guard.applyTimingAllowOriginGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('https 来源合规', () => {
  const headers = { 'timing-allow-origin': 'https://cdn.example.com' };
  const r = guard.applyTimingAllowOriginGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('通配符被拒', () => {
  const headers = { 'timing-allow-origin': '*, https://cdn.example.com' };
  const r = guard.applyTimingAllowOriginGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.WILDCARD);
  assert.strictEqual(headers['timing-allow-origin'], 'https://cdn.example.com');
});

test('明文来源被拒', () => {
  const headers = { 'timing-allow-origin': 'http://cdn.example.com' };
  const r = guard.applyTimingAllowOriginGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['timing-allow-origin'], undefined);
});

test('带端口合规', () => {
  const headers = { 'timing-allow-origin': 'https://cdn.example.com:8443' };
  const r = guard.applyTimingAllowOriginGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('控制字符删除', () => {
  const headers = { 'timing-allow-origin': 'https://a.example.com\u0000' };
  const r = guard.applyTimingAllowOriginGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});

test('超长列表截断', () => {
  const origins = Array.from({ length: 12 }, (_, i) => `https://c${i}.example.com`);
  const headers = { 'timing-allow-origin': origins.join(', ') };
  const r = guard.applyTimingAllowOriginGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
  assert.strictEqual(headers['timing-allow-origin'].split(',').length, 8);
});
