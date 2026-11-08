'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./surrogatecontrolguard');

test('缺省头不动作', () => {
  const headers = {};
  const result = guard.applySurrogateControlGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(result.reason, guard.REASON.MISSING);
});

test('标准指令保留', () => {
  const headers = { 'Surrogate-Control': 'max-age=600' };
  const result = guard.applySurrogateControlGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(headers['Surrogate-Control'], 'max-age=600');
});

test('no-cache 保留', () => {
  const headers = { 'surrogate-control': 'no-cache' };
  const result = guard.applySurrogateControlGuard(headers);
  assert.equal(result.changed, false);
});

test('no-store 覆盖其他指令', () => {
  const headers = { 'Surrogate-Control': 'max-age=600, no-store' };
  const result = guard.applySurrogateControlGuard(headers);
  assert.equal(result.changed, true);
  assert.equal(headers['Surrogate-Control'], 'no-store');
});

test('未知指令被删除', () => {
  const headers = { 'Surrogate-Control': 'public' };
  const result = guard.applySurrogateControlGuard(headers);
  assert.equal(result.reason, guard.REASON.UNKNOWN_DIRECTIVE);
  assert.equal(headers['Surrogate-Control'], undefined);
});

test('max-age 越界被删除', () => {
  const headers = { 'Surrogate-Control': 'max-age=999999' };
  const result = guard.applySurrogateControlGuard(headers);
  assert.equal(result.reason, guard.REASON.BAD_RANGE);
});

test('非数字 max-age 被删除', () => {
  const headers = { 'Surrogate-Control': 'max-age=abc' };
  const result = guard.applySurrogateControlGuard(headers);
  assert.equal(result.reason, guard.REASON.BAD_RANGE);
});

test('stale 越界被删除', () => {
  const headers = { 'Surrogate-Control': 'stale-if-error=9999999' };
  const result = guard.applySurrogateControlGuard(headers);
  assert.equal(result.reason, guard.REASON.BAD_RANGE);
});

test('stale 合法保留', () => {
  const headers = { 'Surrogate-Control': 'max-age=600, stale-while-revalidate=60' };
  const result = guard.applySurrogateControlGuard(headers);
  assert.equal(result.changed, false);
});

test('多值被删除', () => {
  const headers = { 'Surrogate-Control': ['max-age=600', 'no-store'] };
  const result = guard.applySurrogateControlGuard(headers);
  assert.equal(result.reason, guard.REASON.MULTI_VALUE);
});

test('超长取值被删除', () => {
  const headers = { 'Surrogate-Control': 'max-age=' + '9'.repeat(280) };
  const result = guard.applySurrogateControlGuard(headers);
  assert.equal(result.reason, guard.REASON.OVERLONG);
});

test('空值被删除', () => {
  const headers = { 'Surrogate-Control': '   ' };
  const result = guard.applySurrogateControlGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
});

test('非字符串被删除', () => {
  const headers = { 'Surrogate-Control': 9 };
  const result = guard.applySurrogateControlGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
});

test('描述文本覆盖全部分支', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.equal(typeof guard.describeReason(reason), 'string');
  }
});
