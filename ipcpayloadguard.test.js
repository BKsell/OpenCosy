'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./ipcpayloadguard');

test('普通负载通过', () => {
  const r = guard.applyIpcPayloadGuard({ url: 'https://example.com', tabId: 3, active: true });
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('原型污染键名被拒', () => {
  const payload = JSON.parse('{"__proto__":{"polluted":true},"url":"https://example.com"}');
  const r = guard.applyIpcPayloadGuard(payload);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.FORBIDDEN_KEY);
  assert.strictEqual(r.path, '$.__proto__');
});

test('constructor 键名被拒', () => {
  const payload = { constructor: 'x' };
  const r = guard.inspectPayload(payload);
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.reason, guard.REASON.FORBIDDEN_KEY);
});

test('嵌套过深被拒', () => {
  const payload = { a: { b: { c: { d: { e: 1 } } } } };
  const r = guard.applyIpcPayloadGuard(payload);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.TOO_DEEP);
});

test('对象键过多被拒', () => {
  const payload = {};
  for (let i = 0; i < guard.MAX_KEYS + 1; i += 1) payload['k' + i] = i;
  const r = guard.applyIpcPayloadGuard(payload);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY_KEYS);
});

test('字符串超长被拒', () => {
  const r = guard.applyIpcPayloadGuard({ text: 'a'.repeat(guard.MAX_STRING + 1) });
  assert.strictEqual(r.reason, guard.REASON.TOO_LONG_STRING);
});

test('数组元素过多被拒', () => {
  const r = guard.applyIpcPayloadGuard({ items: new Array(guard.MAX_ITEMS + 1).fill(0) });
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY_ITEMS);
});

test('函数参数被拒', () => {
  const r = guard.applyIpcPayloadGuard({ cb: () => {} });
  assert.strictEqual(r.reason, guard.REASON.UNSUPPORTED_TYPE);
});

test('BigInt 参数被拒', () => {
  const r = guard.applyIpcPayloadGuard({ size: 10n });
  assert.strictEqual(r.reason, guard.REASON.UNSUPPORTED_TYPE);
});

test('NaN 被拒', () => {
  const r = guard.applyIpcPayloadGuard({ ratio: Number.NaN });
  assert.strictEqual(r.reason, guard.REASON.NOT_FINITE);
});

test('循环引用被拒', () => {
  const payload = { name: 'loop' };
  payload.self = payload;
  const r = guard.applyIpcPayloadGuard(payload);
  assert.strictEqual(r.reason, guard.REASON.CIRCULAR);
});

test('描述文本覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
