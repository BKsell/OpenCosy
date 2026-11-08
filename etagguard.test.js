'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./etagguard');

function h(value) {
  return { etag: [value] };
}

test('缺头返回 missing', () => {
  const r = guard.applyETagGuard({});
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('普通强校验器不改动', () => {
  const headers = h('"abc123def"');
  const r = guard.applyETagGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.strictEqual(headers.etag[0], '"abc123def"');
});

test('弱校验器保留', () => {
  const r = guard.applyETagGuard(h('W/"abc123"'));
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('未加引号视为非法并剥除', () => {
  const headers = h('abc123');
  const r = guard.applyETagGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers.etag, undefined);
});

test('空引号视为非法', () => {
  const headers = h('""');
  const r = guard.applyETagGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers.etag, undefined);
});

test('暴露绝对路径改为弱校验器', () => {
  const headers = h('"/var/www/app/index.html"');
  const r = guard.applyETagGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.PATH_LEAK);
  assert.ok(headers.etag[0].startsWith('W/"'));
});

test('暴露上层目录改为弱校验器', () => {
  const headers = h('"../../secret.txt"');
  const r = guard.applyETagGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.PATH_LEAK);
  assert.ok(headers.etag[0].startsWith('W/"'));
});

test('纯数字序号校验器被替换', () => {
  const headers = h('"123456789"');
  const r = guard.applyETagGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.PREDICTABLE);
  assert.ok(headers.etag[0].startsWith('W/"'));
});

test('短数字校验器保留', () => {
  const headers = h('"v12"');
  const r = guard.applyETagGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.strictEqual(headers.etag[0], '"v12"');
});

test('控制字符导致剥除', () => {
  const headers = h('"abc\u0007"');
  const r = guard.applyETagGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE_CHARS);
  assert.strictEqual(headers.etag, undefined);
});

test('非 ASCII 校验器被剥除', () => {
  const headers = h('"校验器"');
  const r = guard.applyETagGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE_CHARS);
  assert.strictEqual(headers.etag, undefined);
});

test('超长校验器剥除', () => {
  const headers = h(`"${'a'.repeat(200)}"`);
  const r = guard.applyETagGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
  assert.strictEqual(headers.etag, undefined);
});

test('替换结果稳定可复现', () => {
  const a = guard.applyETagGuard(h('"123456789"'));
  const b = guard.applyETagGuard(h('"123456789"'));
  assert.strictEqual(a.findings[0].tag, b.findings[0].tag);
});

test('describeReason 覆盖主要状态', () => {
  assert.strictEqual(typeof guard.describeReason(guard.REASON.OK), 'string');
  assert.strictEqual(typeof guard.describeReason('unknown'), 'string');
});
