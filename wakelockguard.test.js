'use strict';

// wakelockguard.test.js —— 申请门、隐藏/后台、锁类型、单次/累计时长、重申请节流、释放结算。

const test = require('node:test');
const assert = require('node:assert/strict');
const wl = require('./wakelockguard');
const { WakeLockGuard, WL_REASON, defaultWakeLockPolicy } = wl;

function ctx(over) {
  return Object.assign({
    origin: 'https://video.example.com', isSecureContext: true, blocked: false,
    hasUserGesture: true, isHidden: false, isBackground: false, now: 0,
  }, over || {});
}

test('合法申请放行', () => {
  const g = new WakeLockGuard();
  assert.equal(g.decideRequest(ctx(), 'screen').allowed, true);
  assert.ok(g.isHeld('https://video.example.com'));
});

test('非安全上下文拒绝', () => {
  const g = new WakeLockGuard();
  assert.equal(g.decideRequest(ctx({ isSecureContext: false }), 'screen').reason, WL_REASON.INSECURE_CONTEXT);
});

test('无手势拒绝', () => {
  const g = new WakeLockGuard();
  assert.equal(g.decideRequest(ctx({ hasUserGesture: false }), 'screen').reason, WL_REASON.NO_GESTURE);
});

test('隐藏/后台拒绝', () => {
  const g = new WakeLockGuard();
  assert.equal(g.decideRequest(ctx({ isHidden: true }), 'screen').reason, WL_REASON.HIDDEN_FORBIDDEN);
  assert.equal(g.decideRequest(ctx({ now: 5000, isBackground: true }), 'screen').reason, WL_REASON.HIDDEN_FORBIDDEN);
});

test('错误锁类型拒绝', () => {
  const g = new WakeLockGuard();
  assert.equal(g.decideRequest(ctx({ now: 10000 }), 'system').reason, WL_REASON.WRONG_LOCK_TYPE);
});

test('重复持有拒绝', () => {
  const g = new WakeLockGuard();
  g.decideRequest(ctx({ now: 0 }), 'screen');
  assert.equal(g.decideRequest(ctx({ now: 10000 }), 'screen').reason, WL_REASON.ALREADY_HELD);
});

test('释放结算累计时长，超时 tick 要求释放', () => {
  const g = new WakeLockGuard();
  g.decideRequest(ctx({ now: 0 }), 'screen');
  assert.equal(g.tick('https://video.example.com', 6 * 60000).mustRelease, true);
  const rel = g.noteRelease('https://video.example.com', 6 * 60000);
  assert.equal(rel.heldMs, 6 * 60000);
  assert.ok(!g.isHeld('https://video.example.com'));
});

test('重申请节流', () => {
  const g = new WakeLockGuard();
  g.decideRequest(ctx({ now: 0 }), 'screen');
  g.noteRelease('https://video.example.com', 1000);
  assert.equal(g.decideRequest(ctx({ now: 1500 }), 'screen').reason, WL_REASON.REACQUIRE_THROTTLED);
  assert.equal(g.decideRequest(ctx({ now: 5000 }), 'screen').allowed, true);
});

test('累计时长上限', () => {
  const pol = defaultWakeLockPolicy();
  pol.maxCumulativeMsPerOrigin = 10000;
  pol.reacquireMinIntervalMs = 0;
  const g = new WakeLockGuard(pol);
  g.decideRequest(ctx({ now: 0 }), 'screen');
  g.noteRelease('https://video.example.com', 6000);
  g.decideRequest(ctx({ now: 6000 }), 'screen');
  g.noteRelease('https://video.example.com', 12000);
  assert.equal(g.decideRequest(ctx({ now: 12000 }), 'screen').reason, WL_REASON.CUMULATIVE_LIMIT);
});
