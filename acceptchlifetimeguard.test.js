'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./acceptchlifetimeguard');

test('缺省头不动作', () => {
  const headers = {};
  const result = guard.applyAcceptChLifetimeGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(result.reason, guard.REASON.MISSING);
});

test('合法有效期仍被移除', () => {
  const headers = { 'Accept-CH-Lifetime': '86400' };
  const result = guard.applyAcceptChLifetimeGuard(headers);
  assert.equal(result.changed, true);
  assert.equal(result.reason, guard.REASON.OBSOLETE_HEADER);
  assert.equal(result.seconds, 86400);
  assert.equal(headers['Accept-CH-Lifetime'], undefined);
});

test('大小写键位移除', () => {
  const headers = { 'accept-ch-lifetime': '1000' };
  const result = guard.applyAcceptChLifetimeGuard(headers);
  assert.equal(Object.keys(headers).length, 0);
});

test('有效期越界被标记', () => {
  const headers = { 'Accept-CH-Lifetime': '99999999' };
  const result = guard.applyAcceptChLifetimeGuard(headers);
  assert.equal(result.reason, guard.REASON.BAD_RANGE);
});

test('零值被标记越界', () => {
  const headers = { 'Accept-CH-Lifetime': '0' };
  const result = guard.applyAcceptChLifetimeGuard(headers);
  assert.equal(result.reason, guard.REASON.BAD_RANGE);
});

test('非数字被标记格式错误', () => {
  const headers = { 'Accept-CH-Lifetime': '1h' };
  const result = guard.applyAcceptChLifetimeGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
});

test('多值被删除', () => {
  const headers = { 'Accept-CH-Lifetime': ['86400', '3600'] };
  const result = guard.applyAcceptChLifetimeGuard(headers);
  assert.equal(result.reason, guard.REASON.MULTI_VALUE);
});

test('空值被删除', () => {
  const headers = { 'Accept-CH-Lifetime': '  ' };
  const result = guard.applyAcceptChLifetimeGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
});

test('描述文本覆盖全部分支', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.equal(typeof guard.describeReason(reason), 'string');
  }
});
