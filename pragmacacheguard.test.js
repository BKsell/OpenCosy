'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./pragmacacheguard');

test('缺省头不动作', () => {
  const headers = {};
  const result = guard.applyPragmaCacheGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(result.reason, guard.REASON.MISSING);
});

test('no-cache 保留', () => {
  const headers = { Pragma: 'no-cache' };
  const result = guard.applyPragmaCacheGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(headers.Pragma, 'no-cache');
});

test('大写 no-cache 保留', () => {
  const headers = { pragma: 'NO-CACHE' };
  const result = guard.applyPragmaCacheGuard(headers);
  assert.equal(result.changed, false);
});

test('no-store 非法指令被删除', () => {
  const headers = { Pragma: 'no-store' };
  const result = guard.applyPragmaCacheGuard(headers);
  assert.equal(result.reason, guard.REASON.BAD_DIRECTIVE);
  assert.equal(headers.Pragma, undefined);
});

test('自定义指令被删除', () => {
  const headers = { Pragma: 'x-cache-off' };
  const result = guard.applyPragmaCacheGuard(headers);
  assert.equal(result.reason, guard.REASON.BAD_DIRECTIVE);
});

test('多值被删除', () => {
  const headers = { Pragma: ['no-cache', 'no-store'] };
  const result = guard.applyPragmaCacheGuard(headers);
  assert.equal(result.reason, guard.REASON.MULTI_VALUE);
});

test('逗号合并被删除', () => {
  const headers = { Pragma: 'no-cache,no-store' };
  const result = guard.applyPragmaCacheGuard(headers);
  assert.equal(result.reason, guard.REASON.MULTI_VALUE);
});

test('超长取值被删除', () => {
  const headers = { Pragma: 'n'.repeat(80) };
  const result = guard.applyPragmaCacheGuard(headers);
  assert.equal(result.reason, guard.REASON.OVERLONG);
});

test('空值被删除', () => {
  const headers = { Pragma: '  ' };
  const result = guard.applyPragmaCacheGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
});

test('非字符串被删除', () => {
  const headers = { Pragma: 5 };
  const result = guard.applyPragmaCacheGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
});

test('描述文本覆盖全部分支', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.equal(typeof guard.describeReason(reason), 'string');
  }
});
