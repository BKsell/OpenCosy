'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./contentbaseguard');

test('缺省头不动作', () => {
  const headers = {};
  const result = guard.applyContentBaseGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(result.reason, guard.REASON.MISSING);
});

test('Content-Base 一律删除', () => {
  const headers = { 'Content-Base': 'https://example.com/assets/' };
  const result = guard.applyContentBaseGuard(headers);
  assert.equal(result.changed, true);
  assert.equal(result.reason, guard.REASON.OBSOLETE_HEADER);
  assert.equal(headers['Content-Base'], undefined);
});

test('大小写不敏感删除', () => {
  const headers = { 'content-base': 'http://evil.example/' };
  const result = guard.applyContentBaseGuard(headers);
  assert.equal(result.changed, true);
  assert.equal(Object.keys(headers).length, 0);
});

test('多值被删除并记录来源', () => {
  const headers = { 'Content-Base': ['https://a.example/', 'https://b.example/'] };
  const result = guard.applyContentBaseGuard(headers);
  assert.equal(result.reason, guard.REASON.MULTI_VALUE);
  assert.equal(result.previous.length, 2);
});

test('空值被删除', () => {
  const headers = { 'Content-Base': '   ' };
  const result = guard.applyContentBaseGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
});

test('超长取值被删除', () => {
  const headers = { 'Content-Base': `https://example.com/${'a'.repeat(600)}` };
  const result = guard.applyContentBaseGuard(headers);
  assert.equal(result.reason, guard.REASON.OVERLONG);
});

test('非字符串取值被删除', () => {
  const headers = { 'Content-Base': 123 };
  const result = guard.applyContentBaseGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
});

test('描述文本覆盖全部分支', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.equal(typeof guard.describeReason(reason), 'string');
  }
});
