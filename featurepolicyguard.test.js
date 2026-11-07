'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./featurepolicyguard');

test('缺头不改动', () => {
  const r = guard.applyFeaturePolicyGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合法指令合规', () => {
  const headers = { 'feature-policy': "geolocation 'self'; camera 'none'" };
  const r = guard.applyFeaturePolicyGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('未知特性被剔除', () => {
  const headers = { 'feature-policy': "teleport 'self'; camera 'none'" };
  const r = guard.applyFeaturePolicyGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['feature-policy'], "camera 'none'");
});

test('缺来源列表被剔除', () => {
  const headers = { 'feature-policy': 'camera' };
  const r = guard.applyFeaturePolicyGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['feature-policy'], undefined);
});

test('明文来源被剔除', () => {
  const headers = { 'feature-policy': 'camera http://evil.example' };
  const r = guard.applyFeaturePolicyGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});

test('重复指令去重', () => {
  const headers = { 'feature-policy': "camera 'none'; camera 'self'" };
  const r = guard.applyFeaturePolicyGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
  assert.strictEqual(headers['feature-policy'], "camera 'none'");
});

test('控制字符删除', () => {
  const headers = { 'feature-policy': "camera 'none'\u0000" };
  const r = guard.applyFeaturePolicyGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});
