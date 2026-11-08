'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./contentencodingguard');

function h(value) {
  return { 'content-encoding': [value] };
}

test('无 Content-Encoding 时不变更', () => {
  const headers = { 'content-type': ['text/html'] };
  const r = guard.applyContentEncodingGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('gzip 通过', () => {
  const headers = h('gzip');
  const r = guard.applyContentEncodingGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.deepStrictEqual(r.codings, ['gzip']);
});

test('多层压缩通过', () => {
  const headers = h('deflate, br');
  const r = guard.applyContentEncodingGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.deepStrictEqual(r.codings, ['deflate', 'br']);
});

test('未知算法被移除', () => {
  const headers = h('compress');
  const r = guard.applyContentEncodingGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.UNKNOWN_CODING);
  assert.strictEqual(headers['content-encoding'], undefined);
});

test('重复算法被移除', () => {
  const headers = h('gzip, gzip');
  const r = guard.applyContentEncodingGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
  assert.strictEqual(headers['content-encoding'], undefined);
});

test('层数超预算被移除', () => {
  const headers = h('gzip, br, deflate, zstd');
  const r = guard.applyContentEncodingGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
});

test('空值判格式非法', () => {
  const headers = h('  ');
  const r = guard.applyContentEncodingGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('超长值判格式非法', () => {
  const headers = h(`gzip${'a'.repeat(guard.MAX_VALUE_LENGTH)}`);
  const r = guard.applyContentEncodingGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('identity 合法', () => {
  const headers = h('identity');
  const r = guard.applyContentEncodingGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('大小写不敏感键名被删除', () => {
  const headers = { 'Content-Encoding': ['compress'] };
  const r = guard.applyContentEncodingGuard(headers);
  assert.strictEqual(headers['Content-Encoding'], undefined);
});

test('parseCodings 大小写归一', () => {
  const parsed = guard.parseCodings('GZIP');
  assert.deepStrictEqual(parsed.codings, ['gzip']);
  assert.strictEqual(parsed.reason, guard.REASON.OK);
});

test('describeReason 覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
