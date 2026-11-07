'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./contenttransferencodingguard');

function h(value) {
  return { 'Content-Transfer-Encoding': value };
}

test('binary 直通不改动', () => {
  const headers = h('binary');
  const r = guard.applyTransferEncodingGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.strictEqual(r.token, 'binary');
});

test('8bit 直通不改动', () => {
  const headers = h('8BIT');
  const r = guard.applyTransferEncodingGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('7bit 直通不改动', () => {
  const headers = h('7bit');
  const r = guard.applyTransferEncodingGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('缺少头返回 missing', () => {
  const r = guard.applyTransferEncodingGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
  assert.strictEqual(r.changed, false);
});

test('base64 被视为传统编码并剥除', () => {
  const headers = h('base64');
  const r = guard.applyTransferEncodingGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.LEGACY);
  assert.strictEqual(headers['Content-Transfer-Encoding'], undefined);
});

test('quoted-printable 被剥除', () => {
  const headers = h('quoted-printable');
  const r = guard.applyTransferEncodingGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.LEGACY);
});

test('uuencode 被剥除', () => {
  const headers = h('x-uuencode');
  const r = guard.applyTransferEncodingGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.LEGACY);
});

test('未知取值被剥除', () => {
  const headers = h('gzip');
  const r = guard.applyTransferEncodingGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('逗号列表被剥除', () => {
  const headers = h('binary, base64');
  const r = guard.applyTransferEncodingGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MULTI_VALUE);
});

test('超长字段被剥除', () => {
  const headers = h('b'.repeat(guard.MAX_VALUE_LENGTH + 4));
  const r = guard.applyTransferEncodingGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});

test('空白值被剥除', () => {
  const headers = h('   ');
  const r = guard.applyTransferEncodingGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('数组多头下发被剥除', () => {
  const headers = { 'Content-Transfer-Encoding': ['binary', 'base64'] };
  const r = guard.applyTransferEncodingGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MULTI_VALUE);
  assert.strictEqual(headers['Content-Transfer-Encoding'], undefined);
});

test('小写键名命中', () => {
  const headers = { 'content-transfer-encoding': 'base64' };
  const r = guard.applyTransferEncodingGuard(headers);
  assert.strictEqual(headers['content-transfer-encoding'], undefined);
});

test('describeReason 覆盖分支', () => {
  assert.match(guard.describeReason(guard.REASON.MALFORMED), /非法/);
  assert.match(guard.describeReason(guard.REASON.OVERLONG), /超长/);
  assert.match(guard.describeReason(guard.REASON.LEGACY), /传统编码/);
  assert.match(guard.describeReason(guard.REASON.MULTI_VALUE), /多头/);
  assert.match(guard.describeReason(guard.REASON.MISSING), /未声明/);
  assert.match(guard.describeReason(guard.REASON.OK), /直通/);
});
