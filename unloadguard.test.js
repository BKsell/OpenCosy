'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  UNLOAD_ASK,
  UNLOAD_LEAVE,
  LEAVE_BURST,
  LEAVE_COOLDOWN,
  UNLOAD_BURST_LIMIT,
  UNLOAD_LONG_WINDOW_MS,
  UNLOAD_LONG_LIMIT,
  createUnloadState,
  resetForNavigation,
  decideUnload,
  resetCooldown,
  describeUnloadReason,
} = require('./unloadguard');

const T0 = 4_000_000;

test('正常未保存修改场景给予确认额度', () => {
  const st = createUnloadState(T0);
  const r1 = decideUnload(st, T0 + 100);
  const r2 = decideUnload(st, T0 + 200);
  assert.equal(r1.decision, UNLOAD_ASK);
  assert.equal(r2.decision, UNLOAD_ASK);
  assert.equal(st.askCount, 2);
});

test('短窗口越限后直接放行离开并进入冷却', () => {
  const st = createUnloadState(T0);
  const decisions = [];
  for (let i = 0; i < UNLOAD_BURST_LIMIT + 1; i++) {
    decisions.push(decideUnload(st, T0 + 100 * (i + 1)).decision);
  }
  for (let i = 0; i < UNLOAD_BURST_LIMIT; i++) {
    assert.equal(decisions[i], UNLOAD_ASK);
  }
  assert.equal(decisions[UNLOAD_BURST_LIMIT], UNLOAD_LEAVE);
  assert.equal(st.leaveCount, 1);

  const during = decideUnload(st, T0 + 500);
  assert.equal(during.decision, UNLOAD_LEAVE);
  assert.equal(during.reason, LEAVE_COOLDOWN);
});

test('冷却解除且滑窗过期后恢复确认', () => {
  const st = createUnloadState(T0);
  for (let i = 0; i < UNLOAD_BURST_LIMIT + 1; i++) decideUnload(st, T0 + 100 * (i + 1));
  resetCooldown(st);
  const r = decideUnload(st, T0 + UNLOAD_LONG_WINDOW_MS + 1000);
  assert.equal(r.decision, UNLOAD_ASK);
  assert.equal(r.longCount, 1);
});

test('主导航后配额重置', () => {
  const st = createUnloadState(T0);
  for (let i = 0; i < UNLOAD_BURST_LIMIT + 1; i++) decideUnload(st, T0 + 100 * (i + 1));
  assert.equal(decideUnload(st, T0 + 500).decision, UNLOAD_LEAVE);

  resetForNavigation(st);
  const r = decideUnload(st, T0 + 600);
  assert.equal(r.decision, UNLOAD_ASK);
  assert.equal(r.burstCount, 1);
});

test('低频但持续强留越过长窗口上限', () => {
  const st = createUnloadState(T0);
  let last;
  // 间隔 8s：短窗口内每次仅 1~2 个，长窗口 60s 内累积越限。
  for (let i = 0; i < UNLOAD_LONG_LIMIT + 3; i++) {
    last = decideUnload(st, T0 + 8_000 * (i + 1));
  }
  assert.equal(last.decision, UNLOAD_LEAVE);
  assert.ok(last.reason === LEAVE_BURST || last.reason === LEAVE_COOLDOWN);
});

test('无状态对象默认放行离开（安全侧）', () => {
  const r = decideUnload(null, T0);
  assert.equal(r.decision, UNLOAD_LEAVE);
});

test('原因描述可读', () => {
  for (const reason of [LEAVE_BURST, LEAVE_COOLDOWN]) {
    assert.ok(describeUnloadReason(reason).length > 0);
  }
});
