'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const guard = require('./contentdigestguard');

function sha256Token(payload) {
  const digest = crypto.createHash('sha256').update(payload).digest('base64');
  return `sha-256=:${digest}:`;
}

function h(name, value) {
  return { [name]: [value] };
}

test('缺头返回 missing', () => {
  const r = guard.applyContentDigestGuard({});
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合法 sha-256 摘要不改动', () => {
  const headers = h('content-digest', sha256Token('payload'));
  const r = guard.applyContentDigestGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('repr-digest 走独立入口', () => {
  const headers = h('repr-digest', sha256Token('payload'));
  const r = guard.applyReprDigestGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('sha-512 摘要合法', () => {
  const digest = crypto.createHash('sha512').update('payload').digest('base64');
  const headers = h('content-digest', `sha-512=:${digest}:`);
  const r = guard.applyContentDigestGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('sha-1 弱算法被剥除', () => {
  const headers = h('content-digest', 'sha-1=:q6yYq9f0GSk=:');
  const r = guard.applyContentDigestGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.WEAK_ALGORITHM);
  assert.strictEqual(headers['content-digest'], undefined);
});

test('md5 弱算法被剥除', () => {
  const headers = h('content-digest', 'md5=:XUFAKrxLKna5cZ2REBfFkg==:');
  const r = guard.applyContentDigestGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.WEAK_ALGORITHM);
  assert.strictEqual(headers['content-digest'], undefined);
});

test('不支持的算法被剥除', () => {
  const headers = h('content-digest', 'blake2b=:AAAA:');
  const r = guard.applyContentDigestGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.UNSUPPORTED_ALGORITHM);
});

test('摘要长度不符视为非法', () => {
  const headers = h('content-digest', 'sha-256=:AAAA:');
  const r = guard.applyContentDigestGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers['content-digest'], undefined);
});

test('缺失冒号定界视为非法', () => {
  const headers = h('content-digest', 'sha-256=AAAA');
  const r = guard.applyContentDigestGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('非法 base64 视为非法', () => {
  const headers = h('content-digest', 'sha-256=:!!!!:');
  const r = guard.applyContentDigestGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('弱算法与强算法混合时只保留强算法', () => {
  const headers = h('content-digest', `sha-1=:q6yYq9f0GSk=:, ${sha256Token('payload')}`);
  const r = guard.applyContentDigestGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.WEAK_ALGORITHM);
  assert.ok(headers['content-digest'][0].startsWith('sha-256='));
});

test('重复算法成员只保留首个', () => {
  const members = [];
  for (let i = 0; i < 10; i += 1) {
    members.push(sha256Token(`payload-${i}`));
  }
  const headers = h('content-digest', members.join(', '));
  const r = guard.applyContentDigestGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE_MEMBER);
  assert.strictEqual(headers['content-digest'][0].split(', ').length, 1);
});

test('空取值返回 empty 并剥除', () => {
  const headers = h('content-digest', '   ');
  const r = guard.applyContentDigestGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.EMPTY);
  assert.strictEqual(headers['content-digest'], undefined);
});

test('超长取值整体剥除', () => {
  const headers = h('content-digest', `sha-256=:${'A'.repeat(1200)}:`);
  const r = guard.applyContentDigestGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
  assert.strictEqual(headers['content-digest'], undefined);
});

test('describeReason 覆盖主要状态', () => {
  assert.strictEqual(typeof guard.describeReason(guard.REASON.OK), 'string');
  assert.strictEqual(typeof guard.describeReason('nope'), 'string');
});
