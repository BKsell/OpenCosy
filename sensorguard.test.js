'use strict';

// sensorguard.test.js —— 手势门、后台/iframe、权限态、监听配额、采样节流与量化。

const test = require('node:test');
const assert = require('node:assert/strict');
const s = require('./sensorguard');
const { SensorGuard, quantizeSensorReading, KNOWN_SENSORS, defaultSensorPolicy } = s;

const ctx = (over) => Object.assign({
  origin: 'https://app.example.com',
  isSecureContext: true,
  hasUserGesture: true,
  isBackground: false,
  isTopFrame: true,
  sensorType: 'devicemotion',
  blocked: false,
}, over || {});

test('手势 + 前台 + 顶框允许注册', () => {
  const g = new SensorGuard();
  const r = g.addListener(ctx());
  assert.equal(r.allowed, true);
  assert.equal(r.minIntervalMs, KNOWN_SENSORS.devicemotion.minIntervalMs);
});

test('未知传感器类型拒绝', () => {
  const g = new SensorGuard();
  assert.equal(g.addListener(ctx({ sensorType: 'magical-xyz' })).allowed, false);
});

test('非安全上下文拒绝', () => {
  const g = new SensorGuard();
  const r = g.addListener(ctx({ isSecureContext: false, origin: 'http://app.example.com' }));
  assert.equal(r.reason, 'sensor-insecure-context');
});

test('坏 origin 拒绝', () => {
  const g = new SensorGuard();
  assert.equal(g.addListener(ctx({ origin: 'nope' })).allowed, false);
});

test('无手势拒绝（需要手势的类型）', () => {
  const g = new SensorGuard();
  assert.equal(g.addListener(ctx({ hasUserGesture: false })).reason, 'sensor-no-user-gesture');
});

test('不需要手势的类型无手势也可注册', () => {
  const g = new SensorGuard();
  const r = g.addListener(ctx({ sensorType: 'devicelight', hasUserGesture: false }));
  assert.equal(r.allowed, true);
});

test('后台拒绝', () => {
  const g = new SensorGuard();
  assert.equal(g.addListener(ctx({ isBackground: true })).reason, 'sensor-background-tab');
});

test('iframe 默认拒绝', () => {
  const g = new SensorGuard();
  assert.equal(g.addListener(ctx({ isTopFrame: false })).reason, 'sensor-untrusted-frame');
});

test('权限被拒直接拒绝', () => {
  const g = new SensorGuard(defaultSensorPolicy());
  g.policy.permissionState = 'denied';
  assert.equal(g.addListener(ctx()).reason, 'sensor-permission-denied');
});

test('权限已授予时无手势也允许（iOS requestPermission 已通过）', () => {
  const g = new SensorGuard(defaultSensorPolicy());
  g.policy.permissionState = 'granted';
  const r = g.addListener(ctx({ hasUserGesture: false }));
  assert.equal(r.allowed, true);
});

test('每类型监听数上限', () => {
  const g = new SensorGuard();
  for (let i = 0; i < 4; i++) assert.equal(g.addListener(ctx()).allowed, true);
  assert.equal(g.addListener(ctx()).reason, 'sensor-too-many-listeners');
});

test('移除监听后释放配额', () => {
  const g = new SensorGuard();
  for (let i = 0; i < 4; i++) g.addListener(ctx());
  g.removeListener(ctx().origin, 'devicemotion');
  assert.equal(g.listenerCount(ctx().origin, 'devicemotion'), 3);
  assert.equal(g.addListener(ctx()).allowed, true);
});

test('采样节流：最小间隔内不重复下发', () => {
  const g = new SensorGuard();
  g.addListener(ctx());
  assert.equal(g.shouldEmit(ctx().origin, 'devicemotion', 0), true);
  assert.equal(g.shouldEmit(ctx().origin, 'devicemotion', 10), false);
  assert.equal(g.shouldEmit(ctx().origin, 'devicemotion', 40), true);
});

test('未知类型不应下发', () => {
  const g = new SensorGuard();
  assert.equal(g.shouldEmit(ctx().origin, 'unknown', 0), false);
});

test('resetEmitClock 重置节流窗', () => {
  const g = new SensorGuard();
  g.addListener(ctx());
  g.shouldEmit(ctx().origin, 'devicemotion', 0);
  g.resetEmitClock(ctx().origin);
  assert.equal(g.shouldEmit(ctx().origin, 'devicemotion', 5), true);
});

test('数值量化', () => {
  assert.equal(quantizeSensorReading(0.123456, 0.01), 0.12);
  assert.equal(quantizeSensorReading(7, 5), 5);
  assert.equal(quantizeSensorReading(NaN, 1), NaN);
  assert.equal(quantizeSensorReading(3, 0), 3);
});

test('空上下文拒绝', () => {
  const g = new SensorGuard();
  assert.equal(g.canAddListener(null).allowed, false);
});
