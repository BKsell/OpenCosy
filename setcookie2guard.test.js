'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./setcookie2guard');

test('缺省头不动作', () => {
  const headers = {};
  const result = guard.applySetCookie2Guard(headers);
  assert.equal(result.changed, false);
  assert.equal(result.reason, guard.REASON.MISSING);
});

test('单条 Set-Cookie2 被移除', () => {
  const headers = { 'Set-Cookie2': 'Customer="WILE_E_COYOTE"; Version="1"' };
  const result = guard.applySetCookie2Guard(headers);
  assert.equal(result.changed, true);
  assert.equal(result.reason, guard.REASON.OBSOLETE_HEADER);
  assert.equal(headers['Set-Cookie2'], undefined);
});

test('大小写键位移除', () => {
  const headers = { 'set-cookie2': 'a=b' };
  const result = guard.applySetCookie2Guard(headers);
  assert.equal(Object.keys(headers).length, 0);
});

test('多条目标记多值', () => {
  const headers = { 'Set-Cookie2': ['a=b', 'c=d'] };
  const result = guard.applySetCookie2Guard(headers);
  assert.equal(result.reason, guard.REASON.MULTI_VALUE);
  assert.equal(result.count, 2);
});

test('超量条目标记数量异常', () => {
  const headers = { 'Set-Cookie2': new Array(20).fill('a=b') };
  const result = guard.applySetCookie2Guard(headers);
  assert.equal(result.reason, guard.REASON.OVERSIZED_SET);
  assert.equal(result.count, 20);
});

test('带属性条目仍移除', () => {
  const headers = { 'Set-Cookie2': 'x=y; Domain=example.com; Max-Age=60; Secure' };
  const result = guard.applySetCookie2Guard(headers);
  assert.equal(result.reason, guard.REASON.OBSOLETE_HEADER);
});

test('描述文本覆盖全部分支', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.equal(typeof guard.describeReason(reason), 'string');
  }
});
