'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./xpermittedcrossdomainguard');

function h(value) {
  return { 'X-Permitted-Cross-Domain-Policies': value };
}

test('none 不改动', () => {
  const headers = h('none');
  const r = guard.applyCrossDomainPolicyGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('大写 NONE 放行', () => {
  const headers = h('NONE');
  const r = guard.applyCrossDomainPolicyGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('缺少头返回 missing', () => {
  const r = guard.applyCrossDomainPolicyGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('all 被收紧', () => {
  const headers = h('all');
  const r = guard.applyCrossDomainPolicyGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BROAD_POLICY);
  assert.strictEqual(headers['X-Permitted-Cross-Domain-Policies'], 'none');
});

test('master-only 被收紧', () => {
  const headers = h('master-only');
  const r = guard.applyCrossDomainPolicyGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BROAD_POLICY);
});

test('by-content-type 被收紧', () => {
  const headers = h('by-content-type');
  const r = guard.applyCrossDomainPolicyGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BROAD_POLICY);
});

test('逗号列表含 all 被收紧', () => {
  const headers = h('none, all');
  const r = guard.applyCrossDomainPolicyGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BROAD_POLICY);
});

test('重复 none 被收敛', () => {
  const headers = h('none, none');
  const r = guard.applyCrossDomainPolicyGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MULTI_VALUE);
  assert.strictEqual(headers['X-Permitted-Cross-Domain-Policies'], 'none');
});

test('未知取值被收紧', () => {
  const headers = h('everywhere');
  const r = guard.applyCrossDomainPolicyGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers['X-Permitted-Cross-Domain-Policies'], 'none');
});

test('超长字段被收紧', () => {
  const headers = h('n'.repeat(guard.MAX_VALUE_LENGTH + 4));
  const r = guard.applyCrossDomainPolicyGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});

test('空白值被收紧', () => {
  const headers = h('   ');
  const r = guard.applyCrossDomainPolicyGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('数组多头下发被收敛', () => {
  const headers = { 'X-Permitted-Cross-Domain-Policies': ['all', 'none'] };
  const r = guard.applyCrossDomainPolicyGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MULTI_VALUE);
  assert.strictEqual(headers['X-Permitted-Cross-Domain-Policies'], 'none');
});

test('小写键名命中', () => {
  const headers = { 'x-permitted-cross-domain-policies': 'all' };
  const r = guard.applyCrossDomainPolicyGuard(headers);
  assert.strictEqual(headers['x-permitted-cross-domain-policies'], 'none');
});

test('describeReason 覆盖分支', () => {
  assert.match(guard.describeReason(guard.REASON.MALFORMED), /非法/);
  assert.match(guard.describeReason(guard.REASON.OVERLONG), /超长/);
  assert.match(guard.describeReason(guard.REASON.BROAD_POLICY), /flash/);
  assert.match(guard.describeReason(guard.REASON.MULTI_VALUE), /多头/);
  assert.match(guard.describeReason(guard.REASON.MISSING), /未声明/);
  assert.match(guard.describeReason(guard.REASON.OK), /none/);
});
