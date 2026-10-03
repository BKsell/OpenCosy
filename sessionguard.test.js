'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  PERSIST_PREFIX,
  PARTITION_NAME_MAX,
  POLICY_PERMISSION_DENY,
  POLICY_DEVICE_CANCEL,
  POLICY_OUTGOING_HEADERS,
  ALL_POLICIES,
  REJECT_LENGTH,
  REJECT_CHAR,
  REJECT_EMPTY_PERSIST,
  isValidPartitionNameChar,
  classifyPartition,
  hardeningPlan,
  createSessionGuardState,
  decideSessionHarden,
  isHardened,
} = require('./sessionguard');

test('isValidPartitionNameChar', () => {
  for (const c of ['a', 'Z', '0', '9', '-', '_', '.']) {
    assert.equal(isValidPartitionNameChar(c), true);
  }
  for (const c of [' ', ':', '/', '\\', '@', '\n', '\x00', '中']) {
    assert.equal(isValidPartitionNameChar(c), false);
  }
});

test('classifyPartition 默认会话', () => {
  const empty = classifyPartition('');
  assert.equal(empty.isDefault, true);
  assert.equal(empty.valid, true);
  const undef = classifyPartition(undefined);
  assert.equal(undef.isDefault, true);
  assert.equal(undef.valid, true);
});

test('classifyPartition 持久会话', () => {
  const c = classifyPartition(PERSIST_PREFIX + 'work-a_1');
  assert.equal(c.persist, true);
  assert.equal(c.name, 'work-a_1');
  assert.equal(c.valid, true);
  assert.equal(c.isDefault, false);
});

test('classifyPartition 临时内存会话', () => {
  const c = classifyPartition('guest-2');
  assert.equal(c.persist, false);
  assert.equal(c.valid, true);
  assert.equal(c.name, 'guest-2');
});

test('classifyPartition 拒绝畸形分区', () => {
  assert.equal(classifyPartition(PERSIST_PREFIX).valid, false);
  assert.equal(classifyPartition(PERSIST_PREFIX).reason, REJECT_EMPTY_PERSIST);
  assert.equal(classifyPartition('a/b').reason, REJECT_CHAR);
  assert.equal(classifyPartition('a:b').reason, REJECT_CHAR); // 临时分区不允许冒号
  assert.equal(classifyPartition('a b').reason, REJECT_CHAR);
  assert.equal(classifyPartition('a\nb').reason, REJECT_CHAR);
  assert.equal(classifyPartition(PERSIST_PREFIX + '../etc').reason, REJECT_CHAR);
  assert.equal(classifyPartition('x'.repeat(PARTITION_NAME_MAX + 1)).reason, REJECT_LENGTH);
});

test('hardeningPlan 合法会话全套策略，非法空', () => {
  assert.deepEqual(hardeningPlan(classifyPartition('guest')), ALL_POLICIES.slice());
  assert.deepEqual(hardeningPlan(classifyPartition(PERSIST_PREFIX + 'w')), ALL_POLICIES.slice());
  assert.deepEqual(hardeningPlan(classifyPartition('')), ALL_POLICIES.slice());
  assert.deepEqual(hardeningPlan(classifyPartition('a/b')), []);
  assert.ok(ALL_POLICIES.includes(POLICY_PERMISSION_DENY));
  assert.ok(ALL_POLICIES.includes(POLICY_DEVICE_CANCEL));
  assert.ok(ALL_POLICIES.includes(POLICY_OUTGOING_HEADERS));
});

test('decideSessionHarden 首次加固、重复去重、跨分区独立', () => {
  const st = createSessionGuardState();
  const d1 = decideSessionHarden(st, { partition: 'guest-1' });
  assert.equal(d1.shouldHarden, true);
  assert.equal(d1.alreadyHardened, false);
  assert.equal(d1.policies.length, ALL_POLICIES.length);

  const d2 = decideSessionHarden(st, { partition: 'guest-1' });
  assert.equal(d2.shouldHarden, false);
  assert.equal(d2.alreadyHardened, true);

  const d3 = decideSessionHarden(st, { partition: PERSIST_PREFIX + 'work' });
  assert.equal(d3.shouldHarden, true);

  const d4 = decideSessionHarden(st, { partition: '' });
  assert.equal(d4.shouldHarden, true);
  assert.equal(d4.classification.isDefault, true);

  assert.equal(st.total, 4);
});

test('decideSessionHarden 非法分区不加固并记录拒绝', () => {
  const st = createSessionGuardState();
  const d = decideSessionHarden(st, { partition: '../escape' });
  assert.equal(d.shouldHarden, false);
  assert.equal(d.reason, REJECT_CHAR);
  assert.equal(st.rejected.length, 1);
});

test('decideSessionHarden 拒绝列表有界（不无限增长）', () => {
  const st = createSessionGuardState();
  for (let i = 0; i < 300; i++) {
    decideSessionHarden(st, { partition: 'a/' + i });
  }
  assert.ok(st.rejected.length <= 256);
});

test('isHardened 只读查询', () => {
  const st = createSessionGuardState();
  assert.equal(isHardened(st, 'guest'), false);
  decideSessionHarden(st, { partition: 'guest' });
  assert.equal(isHardened(st, 'guest'), true);
  assert.equal(isHardened(st, 'other'), false);
});

test('decideSessionHarden 缺 sessionLike 按默认会话', () => {
  const st = createSessionGuardState();
  const d = decideSessionHarden(st, null);
  assert.equal(d.classification.isDefault, true);
  assert.equal(d.shouldHarden, true);
});
