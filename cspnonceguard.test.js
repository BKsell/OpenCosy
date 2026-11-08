'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const guard = require('./cspnonceguard');

const NONCE = crypto.randomBytes(16).toString('base64');

test('合法 nonce 与 CSP 通过', () => {
  const csp = "script-src 'nonce-" + NONCE + "' 'strict-dynamic'; object-src 'none'";
  const r = guard.applyCspNonceGuard(csp, NONCE);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('default-src 绑定 nonce 通过', () => {
  const r = guard.inspectCspNonce("default-src 'nonce-" + NONCE + "'", NONCE);
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.directive, 'default-src');
});

test('nonce 为空被拒', () => {
  const r = guard.inspectNonce('');
  assert.strictEqual(r.reason, guard.REASON.EMPTY);
});

test('nonce 非法字符被拒', () => {
  const r = guard.inspectNonce("abc'def");
  assert.strictEqual(r.reason, guard.REASON.BAD_NONCE);
});

test('nonce 熵不足被拒', () => {
  const short = Buffer.alloc(8, 1).toString('base64');
  const r = guard.inspectNonce(short);
  assert.strictEqual(r.reason, guard.REASON.SHORT_NONCE);
});

test('缺少 CSP 被拒', () => {
  const r = guard.inspectCspNonce('', NONCE);
  assert.strictEqual(r.reason, guard.REASON.CSP_MISSING);
});

test('CSP 未绑定 nonce 被拒', () => {
  const r = guard.inspectCspNonce("script-src 'self'", NONCE);
  assert.strictEqual(r.reason, guard.REASON.CSP_NO_NONCE);
});

test('unsafe-inline 被拒', () => {
  const csp = "script-src 'nonce-" + NONCE + "' 'unsafe-inline'";
  const r = guard.inspectCspNonce(csp, NONCE);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE_INLINE);
});

test('通配来源被拒', () => {
  const csp = "default-src *; script-src 'nonce-" + NONCE + "'";
  const r = guard.inspectCspNonce(csp, NONCE);
  assert.strictEqual(r.reason, guard.REASON.WILDCARD);
});

test('重复指令被拒', () => {
  const csp = "script-src 'nonce-" + NONCE + "'; script-src 'self'";
  const r = guard.inspectCspNonce(csp, NONCE);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE_DIRECTIVE);
});

test('描述文本覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
