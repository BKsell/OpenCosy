'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./cspenforceguard');

function h(value) {
  return { 'content-security-policy': [value] };
}

test('缺头不改动', () => {
  const r = guard.applyCspEnforceGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合规策略不改动', () => {
  const headers = h("default-src 'self'; script-src 'self'");
  const r = guard.applyCspEnforceGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('脚本源通配被剔除', () => {
  const headers = h("default-src 'self'; script-src * 'self'");
  const r = guard.applyCspEnforceGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE_SOURCE);
  assert.strictEqual(headers['content-security-policy'], "default-src 'self'; script-src 'self'");
});

test('全部来源不安全时回退 self', () => {
  const headers = h("default-src 'self'; script-src * data:");
  const r = guard.applyCspEnforceGuard(headers);
  assert.strictEqual(headers['content-security-policy'], "default-src 'self'; script-src 'self'");
});

test('缺 default-src 时前置补齐', () => {
  const headers = h("script-src 'self'");
  const r = guard.applyCspEnforceGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.MISSING_DIRECTIVE);
  assert.strictEqual(headers['content-security-policy'], "default-src 'self'; script-src 'self'");
});

test('明文 report-uri 被剔除', () => {
  const headers = h("default-src 'self'; report-uri http://reports.example.com");
  const r = guard.applyCspEnforceGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE_SOURCE);
});

test('超长策略删除', () => {
  const headers = h("default-src 'self';" + " img-src 'self';".repeat(600));
  const r = guard.applyCspEnforceGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
  assert.strictEqual(headers['content-security-policy'], undefined);
});
