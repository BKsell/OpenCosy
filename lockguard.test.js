'use strict';

// lockguard.test.js —— Web Locks：锁名校验、steal、受保护名探测、持有上限、频率、永久持有。

const test = require('node:test');
const assert = require('node:assert/strict');
const l = require('./lockguard');
const { LockGuard, LK_REASON, defaultLockPolicy } = l;

let now = 1000000;
function clock() { return now; }
function ctx(over) {
  return Object.assign({ origin: 'https://app.example.com' }, over || {});
}

test('普通共享锁放行并记账', () => {
  const g = new LockGuard(undefined, clock);
  assert.equal(g.decideRequest(ctx(), 'doc-1', { mode: 'shared' }).decision, 'allow');
  assert.equal(g.heldCount(ctx().origin), 1);
  g.release(ctx(), 'doc-1');
  assert.equal(g.heldCount(ctx().origin), 0);
});

test('锁名非法/超长/控制字符拒绝', () => {
  const g = new LockGuard(undefined, clock);
  assert.equal(g.decideRequest(ctx(), '').reason, LK_REASON.BAD_NAME);
  assert.equal(g.decideRequest(ctx(), 'a'.repeat(300)).reason, LK_REASON.NAME_TOO_LONG);
  assert.equal(g.decideRequest(ctx(), 'a\nb').reason, LK_REASON.NAME_CONTROL_CHAR);
});

test('steal 默认拒绝', () => {
  const g = new LockGuard(undefined, clock);
  assert.equal(g.decideRequest(ctx(), 'x', { steal: true }).reason, LK_REASON.STEAL_NOT_ALLOWED);
});

test('受保护锁名独占探测拒绝', () => {
  const g = new LockGuard(undefined, clock);
  const r = g.decideRequest(ctx(), 'payment-checkout', { mode: 'exclusive', ifAvailable: true });
  assert.equal(r.reason, LK_REASON.EXCLUSIVE_PROBE_DENIED);
  // 普通共享短持仍放行。
  assert.equal(g.decideRequest(ctx(), 'payment-checkout', { mode: 'shared' }).decision, 'allow');
});

test('持有锁上限', () => {
  const pol = defaultLockPolicy();
  pol.maxHeldLocksPerOrigin = 2;
  const g = new LockGuard(pol, clock);
  assert.equal(g.decideRequest(ctx(), 'a').decision, 'allow');
  assert.equal(g.decideRequest(ctx(), 'b').decision, 'allow');
  assert.equal(g.decideRequest(ctx(), 'c').reason, LK_REASON.TOO_MANY_LOCKS);
});

test('永久持有/超长 holdMs 拒绝', () => {
  const g = new LockGuard(undefined, clock);
  assert.equal(g.decideRequest(ctx(), 'a', { holdForever: true }).reason, LK_REASON.HOLD_FOREVER);
  assert.equal(g.decideRequest(ctx(), 'b', { holdMs: 999999 }).reason, LK_REASON.HOLD_FOREVER);
});

test('请求频率上限', () => {
  const pol = defaultLockPolicy();
  pol.maxLockRequestsPerMinute = 3;
  const g = new LockGuard(pol, clock);
  for (let i = 0; i < 3; i++) assert.equal(g.decideRequest(ctx(), 'r' + i).decision, 'allow');
  assert.equal(g.decideRequest(ctx(), 'r3').reason, LK_REASON.RATE_LIMIT);
  now += 61000;
  assert.equal(g.decideRequest(ctx(), 'r4').decision, 'allow');
});

test('同一锁名重复请求不重复计数', () => {
  const pol = defaultLockPolicy();
  pol.maxHeldLocksPerOrigin = 1;
  const g = new LockGuard(pol, clock);
  assert.equal(g.decideRequest(ctx(), 'same').decision, 'allow');
  assert.equal(g.decideRequest(ctx(), 'same').decision, 'allow');
  assert.equal(g.decideRequest(ctx(), 'other').reason, LK_REASON.TOO_MANY_LOCKS);
});
