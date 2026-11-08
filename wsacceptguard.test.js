'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./wsacceptguard');

const VALID_ACCEPT = 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=';

test('缺 accept 返回 missing', () => {
  const r = guard.applySecWebSocketAcceptGuard({});
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合法 accept 不改动', () => {
  const headers = { 'sec-websocket-accept': [VALID_ACCEPT] };
  const r = guard.applySecWebSocketAcceptGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('长度不足视为非法', () => {
  const headers = { 'sec-websocket-accept': ['abc='] };
  const r = guard.applySecWebSocketAcceptGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers['sec-websocket-accept'], undefined);
});

test('缺少填充符视为非法', () => {
  const headers = { 'sec-websocket-accept': [VALID_ACCEPT.slice(0, -1)] };
  const r = guard.applySecWebSocketAcceptGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('通配值视为非法', () => {
  const headers = { 'sec-websocket-accept': ['*'] };
  const r = guard.applySecWebSocketAcceptGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('超长取值视为非法', () => {
  const headers = { 'sec-websocket-accept': [`${VALID_ACCEPT}${'A'.repeat(10)}`] };
  const r = guard.applySecWebSocketAcceptGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});

test('控制字符导致剥除', () => {
  const headers = { 'sec-websocket-accept': [`${VALID_ACCEPT}\u0000`] };
  const r = guard.applySecWebSocketAcceptGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE_CHARS);
  assert.strictEqual(headers['sec-websocket-accept'], undefined);
});

test('缺子协议返回 missing', () => {
  const r = guard.applySecWebSocketProtocolGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合法子协议不改动', () => {
  const headers = { 'sec-websocket-protocol': ['chat, superchat'] };
  const r = guard.applySecWebSocketProtocolGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('非法子协议被剥除', () => {
  const headers = { 'sec-websocket-protocol': ['bad protocol, chat'] };
  const r = guard.applySecWebSocketProtocolGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers['sec-websocket-protocol'][0], 'chat');
});

test('重复子协议去重', () => {
  const headers = { 'sec-websocket-protocol': ['chat, CHAT'] };
  const r = guard.applySecWebSocketProtocolGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
  assert.strictEqual(headers['sec-websocket-protocol'][0], 'chat');
});

test('子协议过多被截断', () => {
  const headers = { 'sec-websocket-protocol': ['a, b, c, d, e, f'] };
  const r = guard.applySecWebSocketProtocolGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
  assert.strictEqual(headers['sec-websocket-protocol'][0].split(', ').length, 4);
});

test('超长子协议被剥除', () => {
  const headers = { 'sec-websocket-protocol': [`${'a'.repeat(80)}, chat`] };
  const r = guard.applySecWebSocketProtocolGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
  assert.strictEqual(headers['sec-websocket-protocol'][0], 'chat');
});

test('控制字符子协议被剥除', () => {
  const headers = { 'sec-websocket-protocol': ['chat\u0007'] };
  const r = guard.applySecWebSocketProtocolGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE_CHARS);
  assert.strictEqual(headers['sec-websocket-protocol'], undefined);
});

test('describeReason 覆盖主要状态', () => {
  assert.strictEqual(typeof guard.describeReason(guard.REASON.OK), 'string');
  assert.strictEqual(typeof guard.describeReason('unknown'), 'string');
});
