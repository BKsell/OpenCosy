'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const d = require('./deviceorientationguard');

test('block-all 直接 deny', () => {
  const r = d.decideSensorAccess({ isSecureContext: true, hasUserGesture: true, policy: 'block-all' });
  assert.equal(r.action, 'deny');
  assert.equal(r.silent, true);
});

test('非安全上下文静默 deny', () => {
  const r = d.decideSensorAccess({ isSecureContext: false, hasUserGesture: true });
  assert.equal(r.action, 'deny');
});

test('无手势静默 deny', () => {
  const r = d.decideSensorAccess({ isSecureContext: true, hasUserGesture: false });
  assert.equal(r.action, 'deny');
  assert.equal(r.silent, true);
});

test('有手势 allow', () => {
  const r = d.decideSensorAccess({ isSecureContext: true, hasUserGesture: true });
  assert.equal(r.action, 'allow');
});

test('allow 策略不压采样', () => {
  assert.equal(d.shouldScrubSensorEvents('allow'), false);
});

test('默认策略压采样', () => {
  assert.equal(d.shouldScrubSensorEvents(), true);
  assert.equal(d.shouldScrubSensorEvents('deny-with-ios-hint'), true);
});
