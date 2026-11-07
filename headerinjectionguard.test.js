'use strict';

const test = require('node:test');
const assert = require('node:assert');

const guard = require('./headerinjectionguard');

test('空响应头不处理', () => {
  const result = guard.applyHeaderInjectionGuard({});
  assert.strictEqual(result.changed, false);
  assert.strictEqual(result.reason, guard.REASON.EMPTY);
});

test('正常头保持不变', () => {
  const headers = { 'Content-Type': 'text/html; charset=utf-8', 'X-Frame-Options': 'DENY' };
  const result = guard.applyHeaderInjectionGuard(headers);
  assert.strictEqual(result.changed, false);
  assert.strictEqual(Object.keys(headers).length, 2);
});

test('CRLF 注入头被移除', () => {
  const headers = { 'X-Test': 'ok\r\nSet-Cookie: evil=1' };
  const result = guard.applyHeaderInjectionGuard(headers);
  assert.strictEqual(result.changed, true);
  assert.strictEqual('X-Test' in headers, false);
});

test('裸 LF 值被移除', () => {
  const headers = { 'X-Test': 'a\nb' };
  const result = guard.applyHeaderInjectionGuard(headers);
  assert.strictEqual(result.reason, guard.REASON.OBS_FOLD);
});

test('NUL 字节被移除', () => {
  const headers = { 'X-Test': 'a\u0000b' };
  const result = guard.applyHeaderInjectionGuard(headers);
  assert.strictEqual(result.reason, guard.REASON.CONTROL_CHAR);
});

test('DEL 字符被移除', () => {
  const headers = { 'X-Test': 'a\u007fb' };
  guard.applyHeaderInjectionGuard(headers);
  assert.strictEqual('X-Test' in headers, false);
});

test('制表符允许保留', () => {
  const headers = { 'X-Test': 'a\tb' };
  const result = guard.applyHeaderInjectionGuard(headers);
  assert.strictEqual(result.changed, false);
});

test('非法头名被移除', () => {
  const headers = { 'X Test': 'ok' };
  const result = guard.applyHeaderInjectionGuard(headers);
  assert.strictEqual(result.reason, guard.REASON.BAD_NAME);
  assert.strictEqual('X Test' in headers, false);
});

test('超长头名被移除', () => {
  const headers = { ['X'.repeat(guard.MAX_NAME_LENGTH + 1)]: 'ok' };
  guard.applyHeaderInjectionGuard(headers);
  assert.strictEqual(Object.keys(headers).length, 0);
});

test('超长头值被移除', () => {
  const headers = { 'X-Test': 'a'.repeat(guard.MAX_VALUE_LENGTH + 1) };
  const result = guard.applyHeaderInjectionGuard(headers);
  assert.strictEqual(result.reason, guard.REASON.OVERLONG);
});

test('数组值逐个检查', () => {
  const headers = { 'Set-Cookie': ['ok=1', 'bad\r\nX: 1'] };
  const result = guard.applyHeaderInjectionGuard(headers);
  assert.strictEqual('Set-Cookie' in headers, false);
  assert.strictEqual(result.changed, true);
});

test('头数量超限整体拒绝', () => {
  const headers = {};
  for (let i = 0; i < guard.MAX_HEADERS + 5; i += 1) {
    headers['X-H' + i] = 'v';
  }
  const result = guard.applyHeaderInjectionGuard(headers);
  assert.strictEqual(result.reason, guard.REASON.TOO_MANY);
  assert.strictEqual(result.removed, 0);
});

test('非字符串值按控制字符处理', () => {
  const headers = { 'X-Test': 42 };
  const result = guard.applyHeaderInjectionGuard(headers);
  assert.strictEqual(result.changed, true);
});

test('scanValue 保留普通文本', () => {
  const scanned = guard.scanValue('text/html; charset=utf-8');
  assert.strictEqual(scanned.reason, guard.REASON.OK);
  assert.strictEqual(scanned.cleaned, 'text/html; charset=utf-8');
});

test('describeReason 覆盖全部原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
