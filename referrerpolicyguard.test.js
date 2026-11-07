'use strict';

const test = require('node:test');
const assert = require('node:assert');

const guard = require('./referrerpolicyguard');

test('缺失时不改动', () => {
  const headers = {};
  const result = guard.applyReferrerPolicyGuard(headers);
  assert.strictEqual(result.changed, false);
  assert.strictEqual(result.reason, guard.REASON.MISSING);
});

test('安全策略保持原样', () => {
  const headers = { 'Referrer-Policy': 'strict-origin-when-cross-origin' };
  const result = guard.applyReferrerPolicyGuard(headers);
  assert.strictEqual(result.changed, false);
  assert.strictEqual(headers['Referrer-Policy'], 'strict-origin-when-cross-origin');
});

test('unsafe-url 收紧', () => {
  const headers = { 'referrer-policy': 'unsafe-url' };
  const result = guard.applyReferrerPolicyGuard(headers);
  assert.strictEqual(result.changed, true);
  assert.strictEqual(result.reason, guard.REASON.UNSAFE);
  assert.strictEqual(headers['referrer-policy'], guard.FALLBACK_POLICY);
});

test('unsafe-url 与安全值混用保留安全值', () => {
  const headers = { 'Referrer-Policy': 'no-referrer, unsafe-url' };
  guard.applyReferrerPolicyGuard(headers);
  assert.strictEqual(headers['Referrer-Policy'], 'no-referrer');
});

test('未知取值被剔除', () => {
  const headers = { 'Referrer-Policy': 'same-origin, wildcard' };
  const result = guard.applyReferrerPolicyGuard(headers);
  assert.strictEqual(result.changed, true);
  assert.strictEqual(result.reason, guard.REASON.UNKNOWN_TOKEN);
  assert.strictEqual(headers['Referrer-Policy'], 'same-origin');
});

test('全为未知取值时回退', () => {
  const headers = { 'Referrer-Policy': 'none, never' };
  const result = guard.applyReferrerPolicyGuard(headers);
  assert.strictEqual(headers['Referrer-Policy'], guard.FALLBACK_POLICY);
  assert.strictEqual(result.reason, guard.REASON.UNKNOWN_TOKEN);
});

test('超长取值回退', () => {
  const headers = { 'Referrer-Policy': 'x'.repeat(guard.MAX_VALUE_LENGTH + 1) };
  const result = guard.applyReferrerPolicyGuard(headers);
  assert.strictEqual(result.reason, guard.REASON.OVERLONG);
  assert.strictEqual(headers['Referrer-Policy'], guard.FALLBACK_POLICY);
});

test('取值过多回退', () => {
  const headers = { 'Referrer-Policy': 'origin, same-origin, no-referrer, origin-when-cross-origin, strict-origin' };
  const result = guard.applyReferrerPolicyGuard(headers);
  assert.strictEqual(result.reason, guard.REASON.TOO_MANY);
  assert.strictEqual(headers['Referrer-Policy'], guard.FALLBACK_POLICY);
});

test('数组重复头被合并', () => {
  const headers = { 'Referrer-Policy': ['no-referrer', 'unsafe-url'] };
  const result = guard.applyReferrerPolicyGuard(headers);
  assert.strictEqual(result.changed, true);
  assert.strictEqual(headers['Referrer-Policy'], guard.FALLBACK_POLICY);
});

test('大小写与空白归一', () => {
  const parsed = guard.parseReferrerPolicy('  NO-REFERRER ,  Same-Origin ');
  assert.strictEqual(parsed.reason, guard.REASON.OK);
  assert.deepStrictEqual(parsed.tokens, ['no-referrer', 'same-origin']);
});

test('空字符串视为缺失', () => {
  const parsed = guard.parseReferrerPolicy('   ');
  assert.strictEqual(parsed.reason, guard.REASON.MISSING);
});

test('非字符串视为畸形', () => {
  const parsed = guard.parseReferrerPolicy(42);
  assert.strictEqual(parsed.reason, guard.REASON.MALFORMED);
});

test('含逗号空段被忽略', () => {
  const parsed = guard.parseReferrerPolicy('no-referrer,,origin');
  assert.strictEqual(parsed.value, 'no-referrer, origin');
});

test('describeReason 覆盖全部原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});

test('安全集合包含 strict-origin', () => {
  assert.ok(guard.SAFE_POLICIES.has('strict-origin'));
  assert.ok(!guard.SAFE_POLICIES.has('unsafe-url'));
});
