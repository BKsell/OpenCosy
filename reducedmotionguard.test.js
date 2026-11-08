'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const m = require('./reducedmotionguard');

test('auto + system reduce 关闭动画', () => {
  const p = m.decideMotionPolicy('auto', true);
  assert.equal(p.animations, 'disable');
  assert.equal(p.autoplay, 'block');
});

test('auto + 系统不 reduce 正常', () => {
  const p = m.decideMotionPolicy('auto', false);
  assert.equal(p.animations, 'allow');
});

test('用户强制 reduce', () => {
  const p = m.decideMotionPolicy('reduce', false);
  assert.equal(p.reason, 'user-forced-reduce');
});

test('用户强制 full 即使系统 reduce', () => {
  const p = m.decideMotionPolicy('full', true);
  assert.equal(p.animations, 'allow');
});

test('重位移类才跳过', () => {
  const reduce = m.decideMotionPolicy('reduce', false);
  assert.equal(m.shouldSkipTransition('slide-in', reduce), true);
  assert.equal(m.shouldSkipTransition('fade-in', reduce), false);
  const normal = m.decideMotionPolicy('auto', false);
  assert.equal(m.shouldSkipTransition('slide-in', normal), false);
});

test('mediaToBoolean', () => {
  assert.equal(m.mediaToBoolean({ matches: true }), true);
  assert.equal(m.mediaToBoolean(false), false);
});
