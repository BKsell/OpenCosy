'use strict';

const test = require('node:test');
const assert = require('node:assert');

const guard = require('./xcontenttypeoptionsguard');

test('缺失时补 nosniff', () => {
  const headers = {};
  const result = guard.applyXContentTypeOptionsGuard(headers);
  assert.strictEqual(result.changed, true);
  assert.strictEqual(headers['X-Content-Type-Options'], 'nosniff');
});

test('已有 nosniff 保持原样', () => {
  const headers = { 'X-Content-Type-Options': 'nosniff' };
  const result = guard.applyXContentTypeOptionsGuard(headers);
  assert.strictEqual(result.changed, false);
});

test('大小写变体归一', () => {
  const headers = { 'x-content-type-options': 'NOSNIFF' };
  const result = guard.applyXContentTypeOptionsGuard(headers);
  assert.strictEqual(result.reason, guard.REASON.OK);
  assert.strictEqual(result.changed, false);
});

test('非法取值被覆盖', () => {
  const headers = { 'X-Content-Type-Options': 'sniff' };
  const result = guard.applyXContentTypeOptionsGuard(headers);
  assert.strictEqual(headers['X-Content-Type-Options'], 'nosniff');
  assert.strictEqual(result.reason, guard.REASON.INVALID);
});

test('空取值被覆盖', () => {
  const headers = { 'X-Content-Type-Options': '   ' };
  guard.applyXContentTypeOptionsGuard(headers);
  assert.strictEqual(headers['X-Content-Type-Options'], 'nosniff');
});

test('重复头被合并', () => {
  const headers = { 'X-Content-Type-Options': ['nosniff', 'sniff'] };
  const result = guard.applyXContentTypeOptionsGuard(headers);
  assert.strictEqual(Array.isArray(headers['X-Content-Type-Options']), false);
  assert.strictEqual(result.reason, guard.REASON.DUPLICATE);
});

test('超长取值被覆盖', () => {
  const headers = { 'X-Content-Type-Options': 'x'.repeat(guard.MAX_VALUE_LENGTH + 1) };
  const result = guard.applyXContentTypeOptionsGuard(headers);
  assert.strictEqual(result.reason, guard.REASON.OVERLONG);
  assert.strictEqual(headers['X-Content-Type-Options'], 'nosniff');
});

test('大小写键被原地改写', () => {
  const headers = { 'X-CONTENT-TYPE-OPTIONS': 'sniff' };
  guard.applyXContentTypeOptionsGuard(headers);
  assert.strictEqual(headers['X-CONTENT-TYPE-OPTIONS'], 'nosniff');
  assert.strictEqual('X-Content-Type-Options' in headers, false);
});

test('非字符串值按非法处理', () => {
  const headers = { 'X-Content-Type-Options': 42 };
  guard.applyXContentTypeOptionsGuard(headers);
  assert.strictEqual(headers['X-Content-Type-Options'], 'nosniff');
});

test('describeReason 覆盖全部原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
