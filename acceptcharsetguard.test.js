'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./acceptcharsetguard');

function h(value) {
  return { 'accept-charset': [value] };
}

test('缺头返回 missing 且不改动', () => {
  const headers = {};
  const r = guard.applyAcceptCharsetGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('任何取值都被整头剥除', () => {
  const headers = h('utf-8');
  const r = guard.applyAcceptCharsetGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.DEPRECATED_HEADER);
  assert.strictEqual(headers['accept-charset'], undefined);
});

test('头键大小写被正确处理', () => {
  const headers = { 'Accept-Charset': ['gzip'] };
  const r = guard.applyAcceptCharsetGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers['Accept-Charset'], undefined);
});

test('通配字符集被识别', () => {
  const r = guard.inspectAcceptCharset('*');
  assert.strictEqual(r.reason, guard.REASON.WILDCARD);
  assert.deepStrictEqual(r.charsets, []);
});

test('未知字符集被识别', () => {
  const r = guard.inspectAcceptCharset('made-up-charset');
  assert.strictEqual(r.reason, guard.REASON.UNKNOWN_CHARSET);
});

test('已知字符集保留', () => {
  const r = guard.inspectAcceptCharset('utf-8, iso-8859-1');
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.deepStrictEqual(r.charsets, ['utf-8', 'iso-8859-1']);
});

test('重复字符集去重', () => {
  const r = guard.inspectAcceptCharset('utf-8, utf-8');
  assert.deepStrictEqual(r.charsets, ['utf-8']);
});

test('带质量参数的字符集被归一化', () => {
  const r = guard.inspectAcceptCharset('utf-8;q=0.9');
  assert.deepStrictEqual(r.charsets, ['utf-8']);
});

test('空值返回 malformed', () => {
  const r = guard.inspectAcceptCharset('   ');
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('超长返回 overlong', () => {
  const r = guard.inspectAcceptCharset('a'.repeat(300));
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});

test('空头仍被剥除', () => {
  const headers = h('   ');
  const r = guard.applyAcceptCharsetGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers['accept-charset'], undefined);
});

test('描述覆盖所有状态', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
