'use strict';

// computepressureguard.test.js —— Compute Pressure：三方/可见、source 白名单、采样间隔、observer 数量。

const test = require('node:test');
const assert = require('node:assert/strict');
const c = require('./computepressureguard');
const { ComputePressureGuard, CU_REASON, defaultComputePressurePolicy } = c;

function ctx(over) {
  return Object.assign({ origin: 'https://app.example.com', isTopFrame: true, visible: true }, over || {});
}

test('合规 cpu 观察放行', () => {
  const g = new ComputePressureGuard();
  assert.equal(g.decideObserve(ctx(), ['cpu'], { sampleInterval: 1000 }).decision, 'allow');
});

test('三方/后台默认拒绝', () => {
  const g = new ComputePressureGuard();
  assert.equal(g.decideObserve(ctx({ isTopFrame: false }), ['cpu'], {}).reason, CU_REASON.THIRD_PARTY);
  assert.equal(g.decideObserve(ctx({ visible: false }), ['cpu'], {}).reason, CU_REASON.BACKGROUND_BLOCKED);
});

test('未知 source 拒绝', () => {
  const g = new ComputePressureGuard();
  assert.equal(g.decideObserve(ctx(), ['thermometer'], {}).reason, CU_REASON.UNKNOWN_SOURCE);
});

test('采样间隔过小拒绝', () => {
  const g = new ComputePressureGuard();
  assert.equal(g.decideObserve(ctx(), ['cpu'], { sampleInterval: 10 }).reason, CU_REASON.INTERVAL_TOO_SMALL);
});

test('observer 数量上限，取消后释放', () => {
  const pol = defaultComputePressurePolicy();
  pol.maxObserversPerOrigin = 1;
  const g = new ComputePressureGuard(pol);
  assert.equal(g.decideObserve(ctx(), ['cpu'], {}).decision, 'allow');
  assert.equal(g.decideObserve(ctx(), ['power'], {}).reason, CU_REASON.TOO_MANY_OBSERVERS);
  g.unobserve(ctx());
  assert.equal(g.decideObserve(ctx(), ['power'], {}).decision, 'allow');
});

test('非 https 拒绝', () => {
  const g = new ComputePressureGuard();
  assert.equal(g.decideObserve({ origin: 'http://x' }, ['cpu'], {}).reason, CU_REASON.INSECURE_ORIGIN);
});
