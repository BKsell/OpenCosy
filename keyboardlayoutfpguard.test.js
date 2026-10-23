'use strict';

// keyboardlayoutfpguard.test.js —— getLayoutMap 门、映射泛化、事件采样频控、物理键去重预算。

const test = require('node:test');
const assert = require('node:assert/strict');
const kl = require('./keyboardlayoutfpguard');
const { KeyboardLayoutFpGuard, KL_REASON, genericLayoutValue, defaultKeyboardLayoutPolicy } = kl;

function ctx(over) {
  return Object.assign({
    origin: 'https://type.example.com', isSecureContext: true, blocked: false,
    hasUserGesture: true, now: 0,
  }, over || {});
}

test('映射值泛化', () => {
  assert.equal(genericLayoutValue('q'), 'x');
  assert.equal(genericLayoutValue('Dead'), 'dead');
  assert.equal(genericLayoutValue(''), '');
});

test('getLayoutMap 默认禁止', () => {
  const g = new KeyboardLayoutFpGuard();
  assert.equal(g.decideGetLayoutMap(ctx()).reason, KL_REASON.LAYOUTMAP_FORBIDDEN);
});

test('开启后无手势拒绝', () => {
  const pol = defaultKeyboardLayoutPolicy();
  pol.allowGetLayoutMap = true;
  const g = new KeyboardLayoutFpGuard(pol);
  assert.equal(g.decideGetLayoutMap(ctx({ hasUserGesture: false })).reason, KL_REASON.LAYOUTMAP_NO_GESTURE);
});

test('开启且有手势放行并提供泛化函数', () => {
  const pol = defaultKeyboardLayoutPolicy();
  pol.allowGetLayoutMap = true;
  const g = new KeyboardLayoutFpGuard(pol);
  const r = g.decideGetLayoutMap(ctx());
  assert.equal(r.allowed, true);
  const gm = g.generalizeMap(new Map([['KeyQ', 'q'], ['ShiftRight', 'Dead']]));
  assert.equal(gm.KeyQ, 'x');
  assert.equal(gm.ShiftRight, 'dead');
});

test('击键采样滑动窗口频控', () => {
  const pol = defaultKeyboardLayoutPolicy();
  pol.maxKeyEventsPerWindow = 3;
  pol.maxDistinctCodesPerOrigin = 1000;
  const g = new KeyboardLayoutFpGuard(pol);
  assert.equal(g.noteKeyEvent(ctx({ now: 0 }), 'KeyA').allowed, true);
  assert.equal(g.noteKeyEvent(ctx({ now: 1 }), 'KeyB').allowed, true);
  assert.equal(g.noteKeyEvent(ctx({ now: 2 }), 'KeyC').allowed, true);
  assert.equal(g.noteKeyEvent(ctx({ now: 3 }), 'KeyD').reason, KL_REASON.EVENT_SAMPLE_THROTTLED);
  // 窗口滑过恢复
  assert.equal(g.noteKeyEvent(ctx({ now: 2000 }), 'KeyE').allowed, true);
});

test('物理键去重预算', () => {
  const pol = defaultKeyboardLayoutPolicy();
  pol.maxKeyEventsPerWindow = 100000;
  pol.maxDistinctCodesPerOrigin = 2;
  const g = new KeyboardLayoutFpGuard(pol);
  assert.equal(g.noteKeyEvent(ctx({ now: 0 }), 'KeyA').allowed, true);
  assert.equal(g.noteKeyEvent(ctx({ now: 1 }), 'KeyB').allowed, true);
  assert.equal(g.noteKeyEvent(ctx({ now: 2 }), 'KeyC').reason, KL_REASON.PROBE_BUDGET_EXCEEDED);
  // 重复键不新增预算
  assert.equal(g.noteKeyEvent(ctx({ now: 3 }), 'KeyA').allowed, true);
  assert.equal(g.distinctCodeCount('https://type.example.com'), 2);
});

test('坏 origin/被拦截拒绝', () => {
  const g = new KeyboardLayoutFpGuard();
  assert.equal(g.noteKeyEvent({ origin: 'bad' }, 'KeyA').reason, KL_REASON.BAD_ORIGIN);
  assert.equal(g.noteKeyEvent(ctx({ blocked: true }), 'KeyA').reason, KL_REASON.BLOCKED_ORIGIN);
});
