'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./acceptrangesguard');

test('缺省头不动作', () => {
  const headers = {};
  const result = guard.applyAcceptRangesGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(result.reason, guard.REASON.MISSING);
});

test('bytes 且声明长度保留', () => {
  const headers = { 'Accept-Ranges': 'bytes', 'Content-Length': '1024' };
  const result = guard.applyAcceptRangesGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(headers['Accept-Ranges'], 'bytes');
});

test('bytes 有内容区间保留', () => {
  const headers = { 'accept-ranges': 'BYTES', 'content-range': 'bytes 0-9/100' };
  const result = guard.applyAcceptRangesGuard(headers);
  assert.equal(result.changed, false);
});

test('bytes 缺少长度证据被删除', () => {
  const headers = { 'Accept-Ranges': 'bytes' };
  const result = guard.applyAcceptRangesGuard(headers);
  assert.equal(result.changed, true);
  assert.equal(result.reason, guard.REASON.UNBACKED_BYTES);
  assert.equal(headers['Accept-Ranges'], undefined);
});

test('none 保留', () => {
  const headers = { 'Accept-Ranges': 'none' };
  const result = guard.applyAcceptRangesGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(result.reason, guard.REASON.NONE_ONLY);
});

test('items 单位被删除', () => {
  const headers = { 'Accept-Ranges': 'items', 'Content-Length': '10' };
  const result = guard.applyAcceptRangesGuard(headers);
  assert.equal(result.reason, guard.REASON.UNKNOWN_UNIT);
});

test('未知单位被删除', () => {
  const headers = { 'Accept-Ranges': 'chapters' };
  const result = guard.applyAcceptRangesGuard(headers);
  assert.equal(result.reason, guard.REASON.UNKNOWN_UNIT);
});

test('多值被删除', () => {
  const headers = { 'Accept-Ranges': ['bytes', 'none'] };
  const result = guard.applyAcceptRangesGuard(headers);
  assert.equal(result.reason, guard.REASON.MULTI_VALUE);
});

test('逗号合并被删除', () => {
  const headers = { 'Accept-Ranges': 'bytes,none' };
  const result = guard.applyAcceptRangesGuard(headers);
  assert.equal(result.reason, guard.REASON.MULTI_VALUE);
});

test('超长取值被删除', () => {
  const headers = { 'Accept-Ranges': 'b'.repeat(80) };
  const result = guard.applyAcceptRangesGuard(headers);
  assert.equal(result.reason, guard.REASON.OVERLONG);
});

test('空值被删除', () => {
  const headers = { 'Accept-Ranges': '   ' };
  const result = guard.applyAcceptRangesGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
});

test('非字符串被删除', () => {
  const headers = { 'Accept-Ranges': 7 };
  const result = guard.applyAcceptRangesGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
});

test('描述文本覆盖全部分支', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.equal(typeof guard.describeReason(reason), 'string');
  }
});
