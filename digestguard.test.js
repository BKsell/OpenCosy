'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./digestguard');

function h(value, name = 'content-digest') {
  return { [name]: [value] };
}

test('无摘要头时不变更', () => {
  const headers = { 'content-type': ['text/html'] };
  const r = guard.applyDigestGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('强算法结构化摘要保留', () => {
  const headers = h('sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:');
  const r = guard.applyDigestGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('弱算法摘要被剥离', () => {
  const headers = h('sha-1=:2jmj7l5rSw0yVb/vlWAYkK/YBwk=:');
  const r = guard.applyDigestGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.WEAK_ALGORITHM);
  assert.strictEqual(headers['content-digest'], undefined);
});

test('混合强弱算法只保留强算法', () => {
  const headers = h('sha-1=:2jmj7l5rSw0yVb/vlWAYkK/YBwk=:, sha-512=:z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYQVWg==:');
  const r = guard.applyDigestGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.WEAK_ALGORITHM);
  assert.strictEqual(headers['content-digest'][0].startsWith('sha-512='), true);
});

test('未知算法按格式非法处理', () => {
  const headers = h('foo-999=:AAAA:');
  const r = guard.applyDigestGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers['content-digest'], undefined);
});

test('缺少等号判非法', () => {
  const headers = h('sha-256');
  const r = guard.applyDigestGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('非法 base64 判非法', () => {
  const headers = h('sha-256=:not base64!!:');
  const r = guard.applyDigestGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('重复算法只保留第一份', () => {
  const headers = h('sha-256=:AAAA:, sha-256=:BBBB:');
  const r = guard.applyDigestGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
  assert.strictEqual(headers['content-digest'][0], 'sha-256=:AAAA:');
});

test('条目数超预算整段移除', () => {
  const entries = [];
  for (let i = 0; i < guard.MAX_ENTRIES + 2; i += 1) entries.push(`sha-256=:AAAA${i}:`);
  const headers = h(entries.join(', '));
  const r = guard.applyDigestGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers['content-digest'], undefined);
});

test('Repr-Digest 同步受检', () => {
  const headers = h('md5=:XUFAKrxLKna5cZ2REBfFkg==:', 'repr-digest');
  const r = guard.applyDigestGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.WEAK_ALGORITHM);
  assert.strictEqual(headers['repr-digest'], undefined);
});

test('旧式 Digest 头同样剥离弱算法', () => {
  const headers = h('SHA-1=2jmj7l5rSw0yVb/vlWAYkK/YBwk=', 'digest');
  const r = guard.applyDigestGuard(headers);
  assert.strictEqual(headers.digest, undefined);
});

test('describeReason 覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
