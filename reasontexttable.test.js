'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { describeReasonFrom, describeReasonTable } = require('./reasontext');

const table = { ok: '状态正常', missing: '缺少取值', '': '空字符串键' };

test('已知键返回表内文案', () => {
  assert.strictEqual(describeReasonFrom(table, 'ok', '兜底'), '状态正常');
  assert.strictEqual(describeReasonFrom(table, 'missing', '兜底'), '缺少取值');
});

test('未知键与空串键都按自身命中判定', () => {
  assert.strictEqual(describeReasonFrom(table, '', '兜底'), '空字符串键');
  assert.strictEqual(describeReasonFrom(table, 'unknown', '兜底'), '兜底');
});

test('原型链属性不误命中', () => {
  for (const key of ['toString', '__proto__', 'hasOwnProperty', 'constructor']) {
    assert.strictEqual(describeReasonFrom(table, key, '兜底'), '兜底', key);
  }
});

test('工厂返回名为 describeReason 的独立函数', () => {
  const a = describeReasonTable({ ok: 'A' }, 'a');
  const b = describeReasonTable({ ok: 'B' }, 'b');
  assert.strictEqual(a.name, 'describeReason');
  assert.strictEqual(a('ok'), 'A');
  assert.strictEqual(b('ok'), 'B');
  assert.strictEqual(a('nope'), 'a');
});
