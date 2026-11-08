'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const q = require('./sessionquarantinetimeout');

test('有效期内 valid', () => {
  const r = q.isTrustStillValid({ grantedAtMs: 1000, nowMs: 2000, ttlMs: 10000 });
  assert.equal(r.valid, true);
});

test('过期 invalid', () => {
  const r = q.isTrustStillValid({ grantedAtMs: 1000, nowMs: 20000, ttlMs: 10000 });
  assert.equal(r.valid, false);
  assert.equal(r.reason, 'expired');
});

test('用户撤销 invalid', () => {
  const r = q.isTrustStillValid({ grantedAtMs: 0, nowMs: 1000, ttlMs: 10000, userRevoked: true });
  assert.equal(r.valid, false);
  assert.equal(r.reason, 'revoked');
});

test('缺失元数据 invalid', () => {
  const r = q.isTrustStillValid({ grantedAtMs: 0, nowMs: 1000, ttlMs: 0 });
  assert.equal(r.valid, false);
});

test('80% 时到刷新点', () => {
  const left = q.nextRefreshPromptInMs({ grantedAtMs: 1000, nowMs: 8900, ttlMs: 10000 });
  assert.equal(left, 100);
});

test('过了刷新点返回 0', () => {
  const left = q.nextRefreshPromptInMs({ grantedAtMs: 0, nowMs: 9000, ttlMs: 10000 });
  assert.equal(left, 0);
});
