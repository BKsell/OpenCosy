'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  FIND_RUN,
  FIND_SKIP_EMPTY,
  FIND_COALESCE,
  FIND_REJECT,
  REJECT_NOT_STRING,
  REJECT_TOO_LONG,
  REJECT_CONTROL,
  HOLD_BURST,
  HOLD_COOLDOWN,
  MAX_FIND_QUERY_LEN,
  FIND_BURST_LIMIT,
  FIND_DUP_MS,
  normalizeFindQuery,
  createFindState,
  decideFind,
  resetFind,
  resetCooldown,
  describeFindReason,
} = require('./findguard');

const T0 = 2_000_000;

test('查询串规整：类型 / 长度 / 控制字符', () => {
  assert.equal(normalizeFindQuery('hello').ok, true);
  assert.equal(normalizeFindQuery('  spaced ').ok, true);

  assert.equal(normalizeFindQuery(undefined).reason, REJECT_NOT_STRING);
  assert.equal(normalizeFindQuery(null).reason, REJECT_NOT_STRING);
  assert.equal(normalizeFindQuery(123).reason, REJECT_NOT_STRING);
  assert.equal(normalizeFindQuery({}).reason, REJECT_NOT_STRING);

  assert.equal(normalizeFindQuery('x'.repeat(MAX_FIND_QUERY_LEN + 1)).reason, REJECT_TOO_LONG);
  assert.equal(normalizeFindQuery('a\x00b').reason, REJECT_CONTROL);
  assert.equal(normalizeFindQuery('line1\nline2').reason, REJECT_CONTROL);
  assert.equal(normalizeFindQuery('esc\x1b').reason, REJECT_CONTROL);
  // 水平 tab 允许进入（Chromium 自身可匹配），由空白处理。
  assert.equal(normalizeFindQuery('a\tb').ok, true);
});

test('正常逐字输入全部放行', () => {
  const st = createFindState(T0);
  for (let i = 1; i <= 8; i++) {
    const r = decideFind(st, { text: 'open'.slice(0, i === 4 ? 4 : i) }, T0 + 120 * i);
    assert.equal(r.decision, FIND_RUN, `第 ${i} 个请求应执行`);
  }
  assert.equal(st.runCount, 8);
});

test('空串与纯空白走清空分支而非拒绝', () => {
  const st = createFindState(T0);
  const r1 = decideFind(st, { text: '' }, T0 + 10);
  const r2 = decideFind(st, { text: '   ' }, T0 + 20);
  assert.equal(r1.decision, FIND_SKIP_EMPTY);
  assert.equal(r2.decision, FIND_SKIP_EMPTY);
  assert.equal(st.runCount, 0);
});

test('非法类型与超长直接拒绝', () => {
  const st = createFindState(T0);
  const r1 = decideFind(st, { text: 42 }, T0 + 10);
  const r2 = decideFind(st, { text: 'x'.repeat(MAX_FIND_QUERY_LEN + 5) }, T0 + 20);
  assert.equal(r1.decision, FIND_REJECT);
  assert.equal(r1.reason, REJECT_NOT_STRING);
  assert.equal(r2.decision, FIND_REJECT);
  assert.equal(r2.reason, REJECT_TOO_LONG);
  assert.equal(st.rejectedCount, 2);
});

test('极短时间内完全相同的连续请求被合并', () => {
  const st = createFindState(T0);
  const r1 = decideFind(st, { text: 'minecraft', matchCase: true }, T0 + 100);
  const r2 = decideFind(st, { text: 'minecraft', matchCase: true }, T0 + 100 + FIND_DUP_MS - 5);
  assert.equal(r1.decision, FIND_RUN);
  assert.equal(r2.decision, FIND_COALESCE);
  assert.equal(st.runCount, 1);
});

test('选项变化不被当作重复合并', () => {
  const st = createFindState(T0);
  decideFind(st, { text: 'abc', matchCase: false }, T0 + 100);
  const r = decideFind(st, { text: 'abc', matchCase: true }, T0 + 101);
  assert.equal(r.decision, FIND_RUN);
});

test('超过去重窗口后同一查询重新执行', () => {
  const st = createFindState(T0);
  decideFind(st, { text: 'abc' }, T0 + 100);
  const r = decideFind(st, { text: 'abc' }, T0 + 100 + FIND_DUP_MS + 50);
  assert.equal(r.decision, FIND_RUN);
});

test('洪泛越限进入冷却，冷却结束后恢复', () => {
  const st = createFindState(T0);
  let blocked;
  for (let i = 0; i < FIND_BURST_LIMIT + 5; i++) {
    const r = decideFind(st, { text: `q${i}` }, T0 + i); // 每毫秒不同查询
    if (r.decision === FIND_REJECT && r.reason === HOLD_BURST) blocked = r;
  }
  assert.ok(blocked, '应出现突发限流');

  const during = decideFind(st, { text: 'later' }, T0 + FIND_BURST_LIMIT + 10);
  assert.equal(during.decision, FIND_REJECT);
  assert.equal(during.reason, HOLD_COOLDOWN);

  resetCooldown(st);
  const recovered = decideFind(st, { text: 'recovered' }, T0 + 5_000);
  assert.equal(recovered.decision, FIND_RUN);
});

test('stopFind 后同一词可以立即重新查找', () => {
  const st = createFindState(T0);
  decideFind(st, { text: 'same' }, T0 + 100);
  const dup = decideFind(st, { text: 'same' }, T0 + 101);
  assert.equal(dup.decision, FIND_COALESCE);
  resetFind(st);
  const again = decideFind(st, { text: 'same' }, T0 + 102);
  assert.equal(again.decision, FIND_RUN);
});

test('空查询在冷却期内也能通过（避免无法清理选中态）', () => {
  const st = createFindState(T0);
  for (let i = 0; i < FIND_BURST_LIMIT + 5; i++) {
    decideFind(st, { text: `q${i}` }, T0 + i);
  }
  const r = decideFind(st, { text: '' }, T0 + FIND_BURST_LIMIT + 10);
  assert.equal(r.decision, FIND_SKIP_EMPTY);
});

test('无状态对象安全拒绝', () => {
  const r = decideFind(null, { text: 'x' }, T0);
  assert.equal(r.decision, FIND_REJECT);
});

test('所有拒绝原因都有可读描述', () => {
  for (const reason of [REJECT_NOT_STRING, REJECT_TOO_LONG, REJECT_CONTROL, HOLD_BURST, HOLD_COOLDOWN]) {
    assert.ok(describeFindReason(reason).length > 0);
  }
});
