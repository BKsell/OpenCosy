'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./xwebkitcspguard');

test('缺省头不动作', () => {
  const headers = { 'Content-Security-Policy': "default-src 'self'" };
  const result = guard.applyXWebKitCspGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(result.reason, guard.REASON.MISSING);
});

test('X-WebKit-CSP 被移除', () => {
  const headers = { 'X-WebKit-CSP': "default-src 'self'" };
  const result = guard.applyXWebKitCspGuard(headers);
  assert.equal(result.changed, true);
  assert.equal(result.reason, guard.REASON.LEGACY_CSP);
  assert.equal(headers['X-WebKit-CSP'], undefined);
});

test('X-Content-Security-Policy 被移除', () => {
  const headers = { 'X-Content-Security-Policy': "allow 'self'" };
  const result = guard.applyXWebKitCspGuard(headers);
  assert.equal(result.reason, guard.REASON.LEGACY_CSP);
  assert.equal(Object.keys(headers).length, 0);
});

test('与标准 CSP 并存时标记冲突', () => {
  const headers = {
    'Content-Security-Policy': "default-src 'self'",
    'x-webkit-csp': "default-src *",
  };
  const result = guard.applyXWebKitCspGuard(headers);
  assert.equal(result.reason, guard.REASON.CONFLICT);
  assert.equal(headers['Content-Security-Policy'], "default-src 'self'");
  assert.equal(headers['x-webkit-csp'], undefined);
});

test('报告模式旧头也被移除', () => {
  const headers = { 'X-WebKit-CSP-Report-Only': "default-src 'none'" };
  const result = guard.applyXWebKitCspGuard(headers);
  assert.equal(result.count, 1);
});

test('同时存在两种旧头时全部移除', () => {
  const headers = {
    'X-WebKit-CSP': "default-src 'self'",
    'X-Content-Security-Policy': "default-src 'self'",
  };
  const result = guard.applyXWebKitCspGuard(headers);
  assert.equal(result.count, 2);
  assert.equal(Object.keys(headers).length, 0);
});

test('描述文本覆盖全部分支', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.equal(typeof guard.describeReason(reason), 'string');
  }
});
