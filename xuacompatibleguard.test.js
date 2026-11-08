'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./xuacompatibleguard');

test('缺省头不动作', () => {
  const headers = {};
  const result = guard.applyXuaCompatibleGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(result.reason, guard.REASON.MISSING);
});

test('IE=edge 保持', () => {
  const headers = { 'X-UA-Compatible': 'IE=edge' };
  const result = guard.applyXuaCompatibleGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(headers['X-UA-Compatible'], 'IE=edge');
});

test('IE=edge 大小写归一化', () => {
  const headers = { 'x-ua-compatible': 'ie=EDGE' };
  const result = guard.applyXuaCompatibleGuard(headers);
  assert.equal(result.changed, true);
  assert.equal(headers['x-ua-compatible'], 'IE=edge');
});

test('EmulateIE7 被删除', () => {
  const headers = { 'X-UA-Compatible': 'IE=EmulateIE7' };
  const result = guard.applyXuaCompatibleGuard(headers);
  assert.equal(result.changed, true);
  assert.equal(result.reason, guard.REASON.LEGACY_MODE);
  assert.equal(headers['X-UA-Compatible'], undefined);
});

test('IE=5 被删除', () => {
  const headers = { 'X-UA-Compatible': 'IE=5' };
  const result = guard.applyXuaCompatibleGuard(headers);
  assert.equal(result.reason, guard.REASON.LEGACY_MODE);
  assert.equal(headers['X-UA-Compatible'], undefined);
});

test('Chrome Frame 被删除', () => {
  const headers = { 'X-UA-Compatible': 'chrome=1' };
  const result = guard.applyXuaCompatibleGuard(headers);
  assert.equal(result.reason, guard.REASON.CHROME_FRAME);
});

test('多值被删除', () => {
  const headers = { 'X-UA-Compatible': ['IE=edge', 'IE=8'] };
  const result = guard.applyXuaCompatibleGuard(headers);
  assert.equal(result.reason, guard.REASON.MULTI_VALUE);
  assert.equal(headers['X-UA-Compatible'], undefined);
});

test('逗号合并值被删除', () => {
  const headers = { 'X-UA-Compatible': 'IE=edge,IE=8' };
  const result = guard.applyXuaCompatibleGuard(headers);
  assert.equal(result.reason, guard.REASON.MULTI_VALUE);
});

test('超长取值被删除', () => {
  const headers = { 'X-UA-Compatible': `IE=${'e'.repeat(200)}` };
  const result = guard.applyXuaCompatibleGuard(headers);
  assert.equal(result.reason, guard.REASON.OVERLONG);
});

test('非法取值被删除', () => {
  const headers = { 'X-UA-Compatible': 'edge-mode' };
  const result = guard.applyXuaCompatibleGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
});

test('非字符串取值被删除', () => {
  const headers = { 'X-UA-Compatible': 42 };
  const result = guard.applyXuaCompatibleGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
});

test('描述文本覆盖全部分支', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.equal(typeof guard.describeReason(reason), 'string');
  }
});
