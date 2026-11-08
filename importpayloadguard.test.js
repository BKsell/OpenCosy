'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./importpayloadguard');

test('合法导入 JSON 通过', () => {
  const r = guard.applyImportPayloadGuard(JSON.stringify({ version: 1, items: [{ url: 'https://a.example/' }] }));
  assert.strictEqual(r.changed, false);
});

test('无效 JSON 被拒', () => {
  const r = guard.applyImportPayloadGuard('{bad}');
  assert.strictEqual(r.changed, true);
});

test('过深嵌套被拒', () => {
  const deep = '['.repeat(200) + '0' + ']'.repeat(200);
  const r = guard.applyImportPayloadGuard(deep);
  assert.strictEqual(r.changed, true);
});

test('原型污染键被拒', () => {
  const r = guard.applyImportPayloadGuard('{"__proto__":{"x":1}}');
  assert.strictEqual(r.changed, true);
});

test('超大字符串被拒', () => {
  const r = guard.applyImportPayloadGuard(JSON.stringify({ note: 'a'.repeat(1100000) }));
  assert.strictEqual(r.changed, true);
});

test('描述存在', () => {
  assert.strictEqual(typeof guard.describeReason('ok'), 'string');
});
