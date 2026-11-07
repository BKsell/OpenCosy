'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./xrobotsguard');

test('缺省头不动作', () => {
  const headers = {};
  const result = guard.applyXRobotsGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(result.reason, guard.REASON.MISSING);
});

test('noindex 保留', () => {
  const headers = { 'X-Robots-Tag': 'noindex' };
  const result = guard.applyXRobotsGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(headers['X-Robots-Tag'], 'noindex');
});

test('组合指令保留', () => {
  const headers = { 'x-robots-tag': 'noindex, nofollow, noarchive' };
  const result = guard.applyXRobotsGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(result.directives.length, 3);
});

test('带爬虫前缀保留', () => {
  const headers = { 'X-Robots-Tag': 'googlebot: noindex' };
  const result = guard.applyXRobotsGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(result.directives[0], 'noindex');
});

test('未知指令被删除', () => {
  const headers = { 'X-Robots-Tag': 'noindex, hide-everything' };
  const result = guard.applyXRobotsGuard(headers);
  assert.equal(result.reason, guard.REASON.UNKNOWN_DIRECTIVE);
  assert.equal(headers['X-Robots-Tag'], undefined);
});

test('数值指令越界被删除', () => {
  const headers = { 'X-Robots-Tag': 'max-snippet: -9' };
  const result = guard.applyXRobotsGuard(headers);
  assert.equal(result.reason, guard.REASON.BAD_RANGE);
});

test('数值指令合法保留', () => {
  const headers = { 'X-Robots-Tag': 'max-snippet: 20' };
  const result = guard.applyXRobotsGuard(headers);
  assert.equal(result.changed, false);
});

test('unavailable_after 合法日期保留', () => {
  const headers = { 'X-Robots-Tag': 'unavailable_after: 25 Jun 2030 15:00:00 PST' };
  const result = guard.applyXRobotsGuard(headers);
  assert.equal(result.changed, false);
});

test('unavailable_after 非法日期被删除', () => {
  const headers = { 'X-Robots-Tag': 'unavailable_after: not-a-date' };
  const result = guard.applyXRobotsGuard(headers);
  assert.equal(result.reason, guard.REASON.BAD_DATE);
});

test('超长取值被删除', () => {
  const headers = { 'X-Robots-Tag': 'noindex,'.repeat(40) };
  const result = guard.applyXRobotsGuard(headers);
  assert.equal(result.reason, guard.REASON.OVERLONG);
});

test('空值被删除', () => {
  const headers = { 'X-Robots-Tag': '  ' };
  const result = guard.applyXRobotsGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
});

test('非字符串被删除', () => {
  const headers = { 'X-Robots-Tag': 12 };
  const result = guard.applyXRobotsGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
});

test('多值被删除', () => {
  const headers = { 'X-Robots-Tag': ['noindex', 'index'] };
  const result = guard.applyXRobotsGuard(headers);
  assert.equal(result.reason, guard.REASON.MULTI_VALUE);
});

test('描述文本覆盖全部分支', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.equal(typeof guard.describeReason(reason), 'string');
  }
});
