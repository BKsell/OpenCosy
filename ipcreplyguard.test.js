'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./ipcreplyguard');

test('普通返回值通过', () => {
  const r = guard.applyReplyGuard({ ok: true, tabs: [{ id: 1, title: 'a' }] });
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.strictEqual(r.json, '{"ok":true,"tabs":[{"id":1,"title":"a"}]}');
});

test('函数返回值被拒', () => {
  const r = guard.applyReplyGuard({ run: function noop() {} });
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.UNSUPPORTED_TYPE);
});

test('Symbol 返回值被拒', () => {
  const r = guard.applyReplyGuard({ token: Symbol('x') });
  assert.strictEqual(r.reason, guard.REASON.UNSUPPORTED_TYPE);
});

test('undefined 顶层被拒', () => {
  const r = guard.applyReplyGuard(undefined);
  assert.strictEqual(r.reason, guard.REASON.UNSUPPORTED_TYPE);
});

test('Infinity 被拒', () => {
  const r = guard.applyReplyGuard({ ratio: Number.POSITIVE_INFINITY });
  assert.strictEqual(r.reason, guard.REASON.NOT_FINITE);
});

test('循环引用被拒', () => {
  const reply = { id: 1 };
  reply.self = reply;
  const r = guard.applyReplyGuard(reply);
  assert.strictEqual(r.reason, guard.REASON.CIRCULAR);
});

test('深层嵌套被拒', () => {
  const reply = { a: { b: { c: { d: { e: { f: 1 } } } } } };
  const r = guard.applyReplyGuard(reply);
  assert.strictEqual(r.reason, guard.REASON.TOO_DEEP);
});

test('超大数组被拒', () => {
  const r = guard.applyReplyGuard({ rows: new Array(guard.MAX_ITEMS + 1).fill(0) });
  assert.strictEqual(r.reason, guard.REASON.TOO_LARGE);
});

test('超大字符串被拒', () => {
  const r = guard.applyReplyGuard({ body: 'x'.repeat(guard.MAX_JSON_BYTES + 1) });
  assert.strictEqual(r.reason, guard.REASON.TOO_LARGE);
});

test('inspectReply 返回字节数', () => {
  const r = guard.inspectReply({ a: '中文' });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.bytes, Buffer.byteLength(r.json, 'utf8'));
});

test('描述文本覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
