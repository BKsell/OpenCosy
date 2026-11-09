const { describeReasonFrom } = require('./reasontext');

const assert = require('node:assert/strict');
const test = require('node:test');

test('describeReasonFrom returns mapped text for own keys', () => {
  const table = { empty: '空值', bad: '非法值' };
  assert.strictEqual(describeReasonFrom(table, 'empty', '未知'), '空值');
  assert.strictEqual(describeReasonFrom(table, 'bad', '未知'), '非法值');
});

test('describeReasonFrom falls back for unknown keys', () => {
  const table = { empty: '空值' };
  assert.strictEqual(describeReasonFrom(table, 'other', '未知'), '未知');
  assert.strictEqual(describeReasonFrom(table, '', '未知'), '未知');
});

test('describeReasonFrom ignores inherited properties', () => {
  const table = { ok: '正常' };
  for (const protoKey of ['constructor', 'toString', '__proto__', 'hasOwnProperty']) {
    assert.strictEqual(describeReasonFrom(table, protoKey, '未知'), '未知', protoKey);
  }
});

test('describeReasonFrom keeps falsy mapped values', () => {
  const table = { zero: 0, blank: '' };
  assert.strictEqual(describeReasonFrom(table, 'zero', '未知'), 0);
  assert.strictEqual(describeReasonFrom(table, 'blank', '未知'), '');
});
