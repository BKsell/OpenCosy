'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const d = require('./taborderdiff');
const {
  MAX_ORDER_IDS,
  MAX_ORDER_ID_LEN,
  hasControlChar,
  isValidOrderId,
  sanitizeOrderIds,
  longestStableSet,
  diffOrder,
  isSameOrder,
} = d;

// 按 diffOrder 返回的 moves 顺序，把 id 依次移动到 afterId 之后（afterId=null 到最前）。
// 仅用于纯重排用例（created/removed 均为空），验证锚点指令应用后必得目标顺序。
function applyMoves(order, moves) {
  const arr = order.slice();
  for (const m of moves) {
    const at = arr.indexOf(m.id);
    if (at !== -1) arr.splice(at, 1);
    if (m.afterId === null) {
      arr.unshift(m.id);
    } else {
      const anchor = arr.indexOf(m.afterId);
      arr.splice(anchor + 1, 0, m.id);
    }
  }
  return arr;
}

// 对一批纯重排用例断言：共有集合不变、应用 moves 后顺序恰为目标序。
function assertReachable(prev, next, expectedMoveCount) {
  const r = diffOrder(prev, next);
  assert.equal(r.ok, true);
  assert.deepEqual(r.created, []);
  assert.deepEqual(r.removed, []);
  if (expectedMoveCount !== undefined) assert.equal(r.moves.length, expectedMoveCount);
  assert.deepEqual(applyMoves(prev, r.moves), next);
  // stable 与 moves 恰好划分共有标签，互不重叠、不遗漏。
  const common = next.filter(id => prev.includes(id));
  assert.equal(r.stable.length + r.moves.length, common.length);
  for (const m of r.moves) assert.equal(r.stable.includes(m.id), false);
  return r;
}

test('hasControlChar / isValidOrderId 判定', () => {
  assert.equal(hasControlChar('tab-1'), false);
  assert.equal(hasControlChar('a\nb'), true);
  assert.equal(hasControlChar('x\x00y'), true);
  assert.equal(isValidOrderId('tab-1'), true);
  assert.equal(isValidOrderId(''), false);
  assert.equal(isValidOrderId(123), false);
  assert.equal(isValidOrderId(null), false);
  assert.equal(isValidOrderId('a\rb'), false);
  assert.equal(isValidOrderId('z'.repeat(MAX_ORDER_ID_LEN + 1)), false);
  assert.equal(isValidOrderId('z'.repeat(MAX_ORDER_ID_LEN)), true);
});

test('sanitizeOrderIds 去非法 / 去重 / 保序 / 截断', () => {
  assert.equal(sanitizeOrderIds('x').ok, false);
  assert.equal(sanitizeOrderIds(null).reason, 'not-array');
  const r = sanitizeOrderIds(['a', 1, '', 'b', 'a', 'c\nd', null, {}]);
  assert.deepEqual(r.value, ['a', 'b']);
  const many = Array.from({ length: MAX_ORDER_IDS + 9 }, (_, i) => 't' + i);
  assert.equal(sanitizeOrderIds(many).value.length, MAX_ORDER_IDS);
});

test('完全一致时 unchanged，无任何指令', () => {
  const r = diffOrder(['a', 'b', 'c'], ['a', 'b', 'c']);
  assert.equal(r.unchanged, true);
  assert.deepEqual(r.moves, []);
  assert.deepEqual(r.stable, ['a', 'b', 'c']);
  assert.equal(isSameOrder(['a', 'b'], ['a', 'b']), true);
});

test('created / removed 按目标与当前顺序上报', () => {
  const r = diffOrder(['a', 'x', 'b'], ['a', 'b', 'c']);
  assert.deepEqual(r.created, ['c']);
  assert.deepEqual(r.removed, ['x']);
  assert.equal(r.unchanged, false);
  assert.equal(isSameOrder(['a', 'x'], ['a', 'c']), false);
});

test('created 标签不计入 moves', () => {
  const r = diffOrder(['a'], ['n', 'a']);
  assert.deepEqual(r.created, ['n']);
  assert.deepEqual(r.moves, []); // a 仍在原位关系，无需移动
});

test('相邻两标签交换，仅一条移动指令', () => {
  assertReachable(['a', 'b', 'c'], ['a', 'c', 'b'], 1);
});

test('整体右移一位（末标签提到最前）只移动一个标签', () => {
  const r = assertReachable(['a', 'b', 'c', 'd'], ['d', 'a', 'b', 'c'], 1);
  assert.deepEqual(r.moves, [{ id: 'd', afterId: null }]);
});

test('首标签沉到末尾，LIS 保住中间三个不动', () => {
  const r = assertReachable(['a', 'b', 'c', 'd'], ['b', 'c', 'd', 'a'], 1);
  assert.deepEqual(r.moves, [{ id: 'a', afterId: 'd' }]);
  assert.deepEqual(r.stable.sort(), ['b', 'c', 'd']);
});

test('完全反转：LIS 长度为 1，移动 n-1 次即可重建目标序', () => {
  const r = assertReachable(['a', 'b', 'c', 'd'], ['d', 'c', 'b', 'a'], 3);
  assert.equal(r.stable.length, 1);
});

test('多个标签穿插重排，指令数为共有数减去 LIS', () => {
  // prev 下标: a0 b1 c2 d3 e4 ; next 共有序列 b,c,e 对应 prev 1,2,4 是 LIS(长度3)
  const prev = ['a', 'b', 'c', 'd', 'e'];
  const next = ['b', 'x', 'c', 'a', 'e', 'd']; // x 是 created，不参与 LIS/moves
  const r = diffOrder(prev, next);
  assert.deepEqual(r.created, ['x']);
  assert.deepEqual(r.removed, []);
  assert.equal(r.stable.length, 3);
  // 手动对纯共有子序列验证可达性（去掉 created x）
  const commonNext = next.filter(id => id !== 'x');
  assert.deepEqual(applyMoves(prev, r.moves), commonNext);
});

test('longestStableSet 直接调用返回相对有序的最大集合', () => {
  const s = longestStableSet(['a', 'b', 'c', 'd'], ['b', 'c', 'd', 'a']);
  assert.equal(s.size, 3);
  assert.equal(s.has('b'), true);
  assert.equal(s.has('c'), true);
  assert.equal(s.has('d'), true);
});

test('脏输入被净化后仍得到自洽结果，不抛错', () => {
  const r = diffOrder(['a', 1, 'b', 'a'], ['b', 'b', 'a', 'c\td']);
  // prev 净化为 [a,b]，next 净化为 [b,a]
  assert.deepEqual(r.prev, ['a', 'b']);
  assert.deepEqual(r.next, ['b', 'a']);
  assert.deepEqual(r.created, []);
  assert.deepEqual(r.removed, []);
  assert.deepEqual(applyMoves(r.prev, r.moves), r.next);
});

test('非数组输入返回失败结构而非抛异常', () => {
  const r = diffOrder(undefined, ['a']);
  assert.equal(r.ok, false);
  assert.equal(r.unchanged, false);
  assert.deepEqual(r.moves, []);
});
