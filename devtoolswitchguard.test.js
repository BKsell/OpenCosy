'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const g = require('./devtoolswitchguard');

test('隔离子窗口打开 DevTools 判定关闭', () => {
  const st = g.createDevtoolsState(0);
  const v = g.evaluateDevtoolsToggle(st, 'opened', { isIsolatedChild: true }, 100);
  assert.equal(v.action, g.DEVTOOLS_CLOSE);
  assert.equal(v.reason, 'devtools-on-isolated-child');
});

test('普通标签打开 DevTools 放行留痕', () => {
  const st = g.createDevtoolsState(0);
  const v = g.evaluateDevtoolsToggle(st, 'opened', {}, 100);
  assert.equal(v.action, g.DEVTOOLS_AUDIT);
  assert.equal(st.isOpen, true);
});

test('主 UI 打开 DevTools 单独标记', () => {
  const st = g.createDevtoolsState(0);
  const v = g.evaluateDevtoolsToggle(st, 'opened', { isMainUI: true }, 100);
  assert.equal(v.action, g.DEVTOOLS_AUDIT);
  assert.equal(v.reason, 'devtools-main-ui');
});

test('关闭事件直接放行并复位', () => {
  const st = g.createDevtoolsState(0);
  g.evaluateDevtoolsToggle(st, 'opened', {}, 100);
  const v = g.evaluateDevtoolsToggle(st, 'closed', {}, 200);
  assert.equal(v.action, g.DEVTOOLS_ALLOW);
  assert.equal(st.isOpen, false);
});

test('打开态重复 opened 幂等', () => {
  const st = g.createDevtoolsState(0);
  g.evaluateDevtoolsToggle(st, 'opened', {}, 100);
  const before = st.openedCount;
  const v = g.evaluateDevtoolsToggle(st, 'opened', {}, 150);
  assert.equal(v.action, g.DEVTOOLS_ALLOW);
  assert.equal(st.openedCount, before);
});

test('未知 phase 放行', () => {
  const st = g.createDevtoolsState(0);
  const v = g.evaluateDevtoolsToggle(st, 'weird', {}, 100);
  assert.equal(v.action, g.DEVTOOLS_ALLOW);
});

test('高频开关触发冷却', () => {
  const st = g.createDevtoolsState(0);
  let cooled = false;
  for (let i = 0; i < g.DEVTOOLS_BURST_MAX; i++) {
    g.evaluateDevtoolsToggle(st, 'opened', {}, 10);
    g.evaluateDevtoolsToggle(st, 'closed', {}, 11);
  }
  // 成对开关后再打开，可能已越短窗阈值。
  const v = g.evaluateDevtoolsToggle(st, 'opened', {}, 12);
  if (v.cooldown || st.cooldownUntil > 0) cooled = true;
  assert.equal(cooled, true);
  // 冷却期隔离窗仍然要求关闭。
  const iso = g.evaluateDevtoolsToggle(st, 'closed', {}, 13);
  const iso2 = g.evaluateDevtoolsToggle(st, 'opened', { isIsolatedChild: true }, 14);
  assert.equal(iso2.action, g.DEVTOOLS_CLOSE);
  assert.equal(iso.action, g.DEVTOOLS_ALLOW);
});

test('长窗慢速累积触发冷却', () => {
  const st = g.createDevtoolsState(0);
  const step = 2000; // 2 秒一次成对，短窗不超
  let cooled = false;
  for (let i = 0; i < g.DEVTOOLS_LONG_MAX + 1; i++) {
    const o = g.evaluateDevtoolsToggle(st, 'opened', {}, i * step);
    const c = g.evaluateDevtoolsToggle(st, 'closed', {}, i * step + 1);
    if (o.cooldown || c.cooldown) cooled = true;
  }
  assert.equal(cooled, true);
});

test('resetForNavigation 只清频率不清打开态', () => {
  const st = g.createDevtoolsState(0);
  g.evaluateDevtoolsToggle(st, 'opened', {}, 100);
  g.resetForNavigation(st, 200);
  assert.equal(st.isOpen, true);
  assert.equal(st.cooldownUntil, 0);
  assert.equal(st.burstCount, 0);
});

test('classifyDevtoolsOpen 分级', () => {
  assert.equal(g.classifyDevtoolsOpen({ isIsolatedChild: true }).decision, g.DEVTOOLS_CLOSE);
  assert.equal(g.classifyDevtoolsOpen({ isMainUI: true }).decision, g.DEVTOOLS_AUDIT);
  assert.equal(g.classifyDevtoolsOpen(null).decision, g.DEVTOOLS_AUDIT);
});
