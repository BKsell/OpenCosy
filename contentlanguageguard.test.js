'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./contentlanguageguard');

function h(value) {
  return { 'Content-Language': value };
}

test('单一合法标签不改动', () => {
  const headers = h('zh-CN');
  const r = guard.applyContentLanguageGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.deepStrictEqual(r.tags, ['zh-CN']);
});

test('多标签按逗号拆分', () => {
  const headers = h('zh-Hans, en, ja-JP');
  const r = guard.applyContentLanguageGuard(headers);
  assert.strictEqual(r.tags.length, 3);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('缺少头返回 missing', () => {
  const r = guard.applyContentLanguageGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
  assert.strictEqual(r.changed, false);
});

test('空白值被剥除', () => {
  const headers = h('   ');
  const r = guard.applyContentLanguageGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers['Content-Language'], undefined);
});

test('通配标签被剥除', () => {
  const headers = h('*');
  const r = guard.applyContentLanguageGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.WILDCARD);
  assert.strictEqual(headers['Content-Language'], undefined);
});

test('非法字符被剥除', () => {
  const headers = h('zh_CN');
  const r = guard.applyContentLanguageGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('数字开头被剥除', () => {
  const headers = h('123');
  const r = guard.applyContentLanguageGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('标签数量超限被剥除', () => {
  const headers = h('en, fr, de, ja, ko, ru');
  const r = guard.applyContentLanguageGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
  assert.strictEqual(headers['Content-Language'], undefined);
});

test('单标签超长被剥除', () => {
  const headers = h(`en-${'x'.repeat(guard.MAX_TAG_LENGTH)}`);
  const r = guard.applyContentLanguageGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});

test('整字段超长被剥除', () => {
  const headers = h(`en-${'x'.repeat(guard.MAX_FIELD_LENGTH)}`);
  const r = guard.applyContentLanguageGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});

test('小写键名命中', () => {
  const headers = { 'content-language': 'zh-CN' };
  const r = guard.applyContentLanguageGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('数组取值取首项', () => {
  const headers = { 'Content-Language': ['zh-CN', 'en'] };
  const r = guard.applyContentLanguageGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.deepStrictEqual(r.tags, ['zh-CN']);
});

test('describeReason 覆盖分支', () => {
  assert.match(guard.describeReason(guard.REASON.MALFORMED), /BCP47/);
  assert.match(guard.describeReason(guard.REASON.OVERLONG), /超长/);
  assert.match(guard.describeReason(guard.REASON.TOO_MANY), /数量/);
  assert.match(guard.describeReason(guard.REASON.WILDCARD), /通配/);
  assert.match(guard.describeReason(guard.REASON.OK), /通过/);
});
