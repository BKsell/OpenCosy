'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  PRINT_ALLOW,
  PRINT_SUPPRESS,
  SUPPRESS_BURST,
  SUPPRESS_LONG,
  SUPPRESS_COOLDOWN,
  PRINT_BURST_WINDOW_MS,
  PRINT_BURST_LIMIT,
  PRINT_LONG_WINDOW_MS,
  PRINT_LONG_LIMIT,
  PRINT_COOLDOWN_MS,
  createPrintState,
  inCooldown,
  decidePrint,
  resetCooldown,
  describePrintReason,
} = require('./printguard');

const T0 = 5_000_000;

test('少量打印正常放行', () => {
  const st = createPrintState(T0);
  const r1 = decidePrint(st, { originUrl: 'https://doc.test/a' }, T0 + 1);
  const r2 = decidePrint(st, { originUrl: 'https://doc.test/a' }, T0 + 2);
  assert.equal(r1.decision, PRINT_ALLOW);
  assert.equal(r2.decision, PRINT_ALLOW);
  assert.equal(st.allowedCount, 2);
  assert.equal(st.origin, 'https://doc.test');
});

test('短窗口连点越过突发上限即抑制并进入冷却', () => {
  const st = createPrintState(T0);
  const decisions = [];
  // 突发上限 PRINT_BURST_LIMIT 次放行，第 LIMIT+1 次被抑制。
  for (let i = 0; i < PRINT_BURST_LIMIT + 1; i++) {
    decisions.push(decidePrint(st, {}, T0 + 100 * (i + 1)).decision);
  }
  for (let i = 0; i < PRINT_BURST_LIMIT; i++) {
    assert.equal(decisions[i], PRINT_ALLOW);
  }
  assert.equal(decisions[PRINT_BURST_LIMIT], PRINT_SUPPRESS);

  // 紧接着再请求应处于冷却，原因为冷却态。
  const cooled = decidePrint(st, {}, T0 + 100 * (PRINT_BURST_LIMIT + 2));
  assert.equal(cooled.decision, PRINT_SUPPRESS);
  assert.equal(cooled.reason, SUPPRESS_COOLDOWN);
  assert.ok(inCooldown(st, T0 + 100 * (PRINT_BURST_LIMIT + 2)));
  assert.ok(cooled.cooldownUntil > T0);
});

test('冷却期结束、时间窗滑过后恢复放行', () => {
  const st = createPrintState(T0);
  // 触发冷却。
  for (let i = 0; i < PRINT_BURST_LIMIT + 1; i++) decidePrint(st, {}, T0 + i);
  const triggerAt = T0 + PRINT_BURST_LIMIT;
  assert.ok(inCooldown(st, triggerAt));
  // 越过冷却与长窗口后，应重新放行。
  const later = triggerAt + PRINT_COOLDOWN_MS + PRINT_LONG_WINDOW_MS + 10;
  assert.equal(inCooldown(st, later), false);
  const r = decidePrint(st, {}, later);
  assert.equal(r.decision, PRINT_ALLOW);
  assert.equal(r.longCount, 1);
});

test('低频但持续打印越过长窗口上限被抑制', () => {
  const st = createPrintState(T0);
  // 间隔大于短窗口（不触发突发），但总量在长窗口内越限。
  let t = T0;
  const step = PRINT_BURST_WINDOW_MS + 100;
  for (let i = 0; i < PRINT_LONG_LIMIT; i++) {
    t += step;
    assert.equal(decidePrint(st, {}, t).decision, PRINT_ALLOW, `第 ${i + 1} 次应放行`);
  }
  t += step;
  const over = decidePrint(st, {}, t);
  assert.equal(over.decision, PRINT_SUPPRESS);
  assert.equal(over.reason, SUPPRESS_LONG);
});

test('被抑制的请求仍计入窗口，防止借抑制绕过统计', () => {
  const st = createPrintState(T0);
  // 直接触发冷却。
  for (let i = 0; i < PRINT_BURST_LIMIT + 1; i++) decidePrint(st, {}, T0 + i);
  const suppressedBefore = st.suppressedCount;
  // 冷却期内狂请求，suppressed 计数持续增加。
  for (let i = 0; i < 10; i++) decidePrint(st, {}, T0 + 100 + i);
  assert.ok(st.suppressedCount > suppressedBefore);
});

test('缺少状态对象时安全失败（抑制而非放行）', () => {
  const r = decidePrint(null, {}, T0);
  assert.equal(r.decision, PRINT_SUPPRESS);
  assert.equal(inCooldown(null, T0), false);
  assert.doesNotThrow(() => resetCooldown(null));
});

test('resetCooldown 可手动解除冷却', () => {
  const st = createPrintState(T0);
  for (let i = 0; i < PRINT_BURST_LIMIT + 1; i++) decidePrint(st, {}, T0 + i);
  assert.ok(inCooldown(st, T0 + PRINT_BURST_LIMIT));
  resetCooldown(st);
  assert.equal(inCooldown(st, T0 + PRINT_BURST_LIMIT), false);
});

test('所有抑制原因都有中文说明', () => {
  for (const reason of [SUPPRESS_BURST, SUPPRESS_LONG, SUPPRESS_COOLDOWN]) {
    assert.ok(describePrintReason(reason).includes('打印'), `${reason} 缺说明`);
  }
  assert.ok(describePrintReason('nope').length > 0);
});
