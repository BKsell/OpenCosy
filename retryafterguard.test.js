'use strict';

const test = require('node:test');
const assert = require('node:assert');

const guard = require('./retryafterguard');

test('缺失时不改动', () => {
  const headers = {};
  const result = guard.applyRetryAfterGuard(headers);
  assert.strictEqual(result.changed, false);
  assert.strictEqual(result.reason, guard.REASON.MISSING);
});

test('正常秒数保留', () => {
  const headers = { 'Retry-After': '120' };
  const result = guard.applyRetryAfterGuard(headers);
  assert.strictEqual(result.changed, false);
  assert.strictEqual(result.seconds, 120);
});

test('零秒保留', () => {
  const headers = { 'retry-after': '0' };
  const result = guard.applyRetryAfterGuard(headers);
  assert.strictEqual(result.changed, false);
});

test('负数被移除', () => {
  const headers = { 'Retry-After': '-5' };
  const result = guard.applyRetryAfterGuard(headers);
  assert.strictEqual(result.changed, true);
  assert.strictEqual('Retry-After' in headers, false);
  assert.strictEqual(result.reason, guard.REASON.NEGATIVE);
});

test('超大秒数被截断', () => {
  const headers = { 'Retry-After': '999999' };
  const result = guard.applyRetryAfterGuard(headers);
  assert.strictEqual(headers['Retry-After'], String(guard.MAX_DELAY_SECONDS));
  assert.strictEqual(result.reason, guard.REASON.TOO_FAR);
});

test('非法文本被移除', () => {
  const headers = { 'Retry-After': 'soon' };
  guard.applyRetryAfterGuard(headers);
  assert.strictEqual('Retry-After' in headers, false);
});

test('超长取值被移除', () => {
  const headers = { 'Retry-After': '1'.repeat(guard.MAX_VALUE_LENGTH + 1) };
  const result = guard.applyRetryAfterGuard(headers);
  assert.strictEqual(result.reason, guard.REASON.OVERLONG);
  assert.strictEqual('Retry-After' in headers, false);
});

test('合法 HTTP 日期按差值计算', () => {
  const now = Date.parse('Wed, 21 Oct 2026 07:28:00 GMT');
  const headers = { 'Retry-After': 'Wed, 21 Oct 2026 07:29:00 GMT' };
  const result = guard.applyRetryAfterGuard(headers, now);
  assert.strictEqual(result.seconds, 60);
  assert.strictEqual(result.changed, false);
});

test('过期 HTTP 日期被移除', () => {
  const now = Date.parse('Wed, 21 Oct 2026 07:30:00 GMT');
  const headers = { 'Retry-After': 'Wed, 21 Oct 2026 07:28:00 GMT' };
  const result = guard.applyRetryAfterGuard(headers, now);
  assert.strictEqual(result.reason, guard.REASON.NEGATIVE);
  assert.strictEqual('Retry-After' in headers, false);
});

test('畸形日期被移除', () => {
  const headers = { 'Retry-After': '2026-10-21 07:28:00' };
  const result = guard.applyRetryAfterGuard(headers);
  assert.strictEqual(result.reason, guard.REASON.BAD_DATE);
  assert.strictEqual('Retry-After' in headers, false);
});

test('远期日期被截断', () => {
  const now = Date.parse('Wed, 21 Oct 2026 07:28:00 GMT');
  const headers = { 'Retry-After': 'Fri, 21 Oct 2027 07:28:00 GMT' };
  const result = guard.applyRetryAfterGuard(headers, now);
  assert.strictEqual(result.reason, guard.REASON.TOO_FAR);
  assert.strictEqual(headers['Retry-After'], String(guard.MAX_DELAY_SECONDS));
});

test('数组取首值', () => {
  const headers = { 'Retry-After': ['60', '120'] };
  const result = guard.applyRetryAfterGuard(headers);
  assert.strictEqual(result.seconds, 60);
});

test('parseRetryAfter 处理非字符串', () => {
  const parsed = guard.parseRetryAfter(123);
  assert.strictEqual(parsed.reason, guard.REASON.MALFORMED);
});

test('describeReason 覆盖全部原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
