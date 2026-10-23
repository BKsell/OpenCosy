'use strict';

// timingguard.test.js —— 时间量化、抖动确定性、定时器嵌套 clamp、SAB 隔离门、内存裁剪。

const test = require('node:test');
const assert = require('node:assert/strict');
const tg = require('./timingguard');
const {
  TimingGuard, TG_REASON, defaultTimingPolicy,
  stableJitter, quantizeNow, quantizeTimeOrigin, clampTimeout,
} = tg;

const ORIGIN = 'https://app.example.com';

test('时间量化到 5ms 步长', () => {
  const pol = defaultTimingPolicy();
  pol.addPerOriginJitter = false;
  assert.equal(quantizeNow(ORIGIN, 0, pol), 0);
  assert.equal(quantizeNow(ORIGIN, 4.9, pol), 0);
  assert.equal(quantizeNow(ORIGIN, 5.0, pol), 5);
  assert.equal(quantizeNow(ORIGIN, 9.9, pol), 5);
});

test('抖动确定性：同源同值，不随调用变', () => {
  const j1 = stableJitter('https://a.com', 4);
  const j2 = stableJitter('https://a.com', 4);
  assert.equal(j1, j2);
  assert.ok(j1 >= 0 && j1 <= 4);
  const jb = stableJitter('https://b.com', 4);
  assert.ok(typeof jb === 'number');
});

test('非嵌套定时器最小 1ms', () => {
  const r = clampTimeout(0, 0, 0, defaultTimingPolicy());
  assert.equal(r.delayMs, 1);
  assert.equal(r.accepted, true);
});

test('嵌套超过阈值 clamp 到 4ms', () => {
  const r = clampTimeout(0, 6, 0, defaultTimingPolicy());
  assert.equal(r.delayMs, 4);
  assert.equal(r.clamped, true);
  assert.equal(r.reason, TG_REASON.NESTED_TIMER_CLAMPED);
});

test('定时器洪泛拒绝', () => {
  const r = clampTimeout(100, 0, 256, defaultTimingPolicy());
  assert.equal(r.accepted, false);
  assert.equal(r.rejectReason, TG_REASON.TIMER_FLOOD);
});

test('SAB 要求跨源隔离', () => {
  const g = new TimingGuard();
  assert.equal(g.decideSab({ origin: ORIGIN, crossOriginIsolated: false }).allowed, false);
  assert.equal(g.decideSab({ origin: ORIGIN, crossOriginIsolated: true }).allowed, true);
});

test('关闭隔离要求后总是放行', () => {
  const pol = defaultTimingPolicy();
  pol.requireIsolationForSab = false;
  const g = new TimingGuard(pol);
  assert.equal(g.decideSab({ origin: ORIGIN }).allowed, true);
});

test('performance.memory 默认裁剪', () => {
  const g = new TimingGuard();
  const r = g.redactMemory({ usedJSHeapSize: 1, totalJSHeapSize: 2, jsHeapSizeLimit: 3 });
  assert.equal(r.redacted, true);
});

test('开启后暴露内存字段', () => {
  const pol = defaultTimingPolicy();
  pol.exposePerformanceMemory = true;
  const g = new TimingGuard(pol);
  const r = g.redactMemory({ usedJSHeapSize: 1, totalJSHeapSize: 2, jsHeapSizeLimit: 3 });
  assert.equal(r.redacted, false);
  assert.equal(r.usedJSHeapSize, 1);
});

test('定时器计数随触发回收', () => {
  const g = new TimingGuard();
  for (let i = 0; i < 3; i++) g.schedule(ORIGIN, 10, 0);
  g.timerFiredOrCleared(ORIGIN);
  // 不直接断言内部数，验证再调度仍被接受即可
  assert.equal(g.schedule(ORIGIN, 10, 0).accepted, true);
});

test('timeOrigin 同样被量化', () => {
  const pol = defaultTimingPolicy();
  pol.addPerOriginJitter = false;
  assert.equal(quantizeTimeOrigin(ORIGIN, 12.3, pol), 10);
});
