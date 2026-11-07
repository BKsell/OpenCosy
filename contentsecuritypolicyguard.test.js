'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./contentsecuritypolicyguard');

function h(value) {
  return { 'content-security-policy': [value] };
}

test('缺头不改动', () => {
  const r = guard.applyContentSecurityPolicyGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合规策略不改动', () => {
  const headers = h("default-src 'self'; script-src 'self' https://static.example.com");
  const r = guard.applyContentSecurityPolicyGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('未知指令被剔除', () => {
  const headers = h("default-src 'self'; script-src-evil *");
  const r = guard.applyContentSecurityPolicyGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.UNKNOWN_DIRECTIVE);
  assert.strictEqual(headers['content-security-policy'], "default-src 'self'");
});

test('重复指令保留首个', () => {
  const headers = h("default-src 'self'; img-src 'self'; img-src *");
  const r = guard.applyContentSecurityPolicyGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE_DIRECTIVE);
  assert.strictEqual(headers['content-security-policy'], "default-src 'self'; img-src 'self'");
});

test('空指令被剔除', () => {
  const headers = h("default-src 'self'; script-src");
  const r = guard.applyContentSecurityPolicyGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.EMPTY_DIRECTIVE);
  assert.strictEqual(headers['content-security-policy'], "default-src 'self'");
});

test('仅保留布尔指令', () => {
  const headers = h('upgrade-insecure-requests; sandbox');
  const r = guard.applyContentSecurityPolicyGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('超长策略删除', () => {
  const headers = h("default-src 'self';" + " img-src 'self';".repeat(600));
  const r = guard.applyContentSecurityPolicyGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});
