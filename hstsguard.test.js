'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./hstsguard');

function h(value) {
  return { 'strict-transport-security': [value] };
}

test('无 HSTS 时不变更', () => {
  const headers = { 'content-type': ['text/html'] };
  const r = guard.applyHstsGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('正常 HSTS 保留', () => {
  const headers = h('max-age=31536000; includeSubDomains');
  const r = guard.applyHstsGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.strictEqual(r.verdict.maxAge, 31536000);
  assert.strictEqual(r.verdict.includeSubDomains, true);
});

test('max-age=0 被移除', () => {
  const headers = h('max-age=0');
  const r = guard.applyHstsGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DISABLED);
  assert.strictEqual(headers['strict-transport-security'], undefined);
});

test('短有效期被判禁用', () => {
  const headers = h('max-age=60');
  const r = guard.applyHstsGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DISABLED);
});

test('缺少 max-age 判非法', () => {
  const headers = h('includeSubDomains');
  const r = guard.applyHstsGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('max-age 非数字判非法', () => {
  const headers = h('max-age=abc');
  const r = guard.applyHstsGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('重复指令判非法', () => {
  const headers = h('max-age=31536000; max-age=31536000');
  const r = guard.applyHstsGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
});

test('超长值判非法', () => {
  const headers = h(`max-age=31536000;${'a'.repeat(guard.MAX_VALUE_LENGTH)}`);
  const r = guard.applyHstsGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('引号包裹的 max-age 被接受', () => {
  const parsed = guard.parseHsts('max-age="31536000"');
  assert.strictEqual(parsed.reason, guard.REASON.OK);
  assert.strictEqual(parsed.maxAge, 31536000);
});

test('大小写不敏感键名被删除', () => {
  const headers = { 'Strict-Transport-Security': ['max-age=0'] };
  const r = guard.applyHstsGuard(headers);
  assert.strictEqual(headers['Strict-Transport-Security'], undefined);
});

test('describeReason 覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
