'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./csvformulaguard');

test('普通文本不变更', () => {
  const r = guard.guardRow(['name', 'url', 'count']);
  assert.strictEqual(r.changed, false);
  assert.deepStrictEqual(r.cells, ['name', 'url', 'count']);
});

test('等号公式被转义', () => {
  const r = guard.applyCsvFormulaGuard([['=1+1']]);
  assert.strictEqual(r.changed, true);
  assert.deepStrictEqual(r.rows[0], ["'=1+1"]);
  assert.strictEqual(r.reason, guard.REASON.FORMULA_ESCAPED);
});

test('加号前缀被转义', () => {
  const r = guard.inspectCell('+cmd|calc');
  assert.strictEqual(r.reason, guard.REASON.FORMULA_ESCAPED);
  assert.strictEqual(r.text, "'+cmd|calc");
});

test('减号与 @ 前缀被转义', () => {
  for (const value of ['-2+3', '@SUM(A1)']) {
    const r = guard.inspectCell(value);
    assert.strictEqual(r.reason, guard.REASON.FORMULA_ESCAPED);
  }
});

test('制表符前缀被转义', () => {
  const r = guard.inspectCell('\t=cmd');
  assert.strictEqual(r.reason, guard.REASON.FORMULA_ESCAPED);
});

test('控制字符被清除', () => {
  const r = guard.inspectCell('a\u0007b');
  assert.strictEqual(r.reason, guard.REASON.CONTROL_STRIPPED);
  assert.strictEqual(r.text, 'ab');
});

test('超长单元格被拒', () => {
  const r = guard.inspectCell('a'.repeat(guard.MAX_CELL_LENGTH + 1));
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.reason, guard.REASON.TOO_LONG_CELL);
});

test('非列表行被标注', () => {
  const r = guard.guardRow('a,b');
  assert.strictEqual(r.reason, guard.REASON.NOT_LIST);
});

test('非列表矩阵被标注', () => {
  const r = guard.guardMatrix('a,b');
  assert.strictEqual(r.reason, guard.REASON.NOT_LIST);
});

test('多行矩阵逐行处理', () => {
  const r = guard.guardMatrix([['ok', '=evil'], ['fine', 'x']]);
  assert.strictEqual(r.changed, true);
  assert.deepStrictEqual(r.rows[0], ['ok', "'=evil"]);
  assert.deepStrictEqual(r.rows[1], ['fine', 'x']);
});

test('描述文本覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
