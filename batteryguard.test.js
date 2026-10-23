'use strict';

// batteryguard.test.js —— 读取/监听门、频控、电量与时间降熵、网络信息裁剪。

const test = require('node:test');
const assert = require('node:assert/strict');
const bg = require('./batteryguard');
const {
  BatteryGuard, BG_REASON, defaultBatteryPolicy,
  quantizeLevel, quantizeTimeMs, redactBattery, redactNetwork,
} = bg;

const ORIGIN = 'https://news.example.com';
function ctx(over) {
  return Object.assign({
    origin: ORIGIN, isSecureContext: true, isBackground: false, blocked: false, now: 0,
  }, over || {});
}

test('电量量化到 0.25 档', () => {
  assert.equal(quantizeLevel(0, 0.25), 0);
  assert.equal(quantizeLevel(0.12, 0.25), 0);
  assert.equal(quantizeLevel(0.13, 0.25), 0.25);
  assert.equal(quantizeLevel(0.9, 0.25), 1);
  assert.equal(quantizeLevel(2, 0.25), 1);
  assert.equal(quantizeLevel(-1, 0.25), 0);
});

test('时间量化到步长，Infinity 保留', () => {
  assert.equal(quantizeTimeMs(0, 600000), 0);
  assert.equal(quantizeTimeMs(300000, 600000), 0);
  assert.equal(quantizeTimeMs(300001, 600000), 0);
  assert.equal(quantizeTimeMs(600000, 600000), 600000);
  assert.equal(quantizeTimeMs(Infinity, 600000), Infinity);
  assert.equal(quantizeTimeMs(-5, 600000), Infinity);
});

test('电池快照降熵：非充电只给放电时间', () => {
  const snap = redactBattery({ level: 0.37, charging: false, chargingTime: 0, dischargingTime: 4200000 }, defaultBatteryPolicy());
  assert.equal(snap.level, 0.25);
  assert.equal(snap.charging, false);
  assert.equal(snap.dischargingTime, 4200000);
  assert.equal(snap.chargingTime, undefined);
});

test('关闭充电状态后不暴露布尔与时间', () => {
  const pol = defaultBatteryPolicy();
  pol.exposeChargingState = false;
  const snap = redactBattery({ level: 0.5, charging: true, chargingTime: 1000 }, pol);
  assert.equal(snap.charging, undefined);
  assert.equal(snap.chargingTime, undefined);
});

test('网络信息默认不暴露 rtt，downlink 量化', () => {
  const n = redactNetwork({ effectiveType: '4g', rtt: 123, downlink: 7.6, saveData: false }, defaultBatteryPolicy());
  assert.equal(n.effectiveType, '4g');
  assert.equal(n.rtt, undefined);
  assert.equal(n.downlink, 8);
});

test('允许 rtt 时量化到 50ms', () => {
  const pol = defaultBatteryPolicy();
  pol.exposeNetworkRtt = true;
  const n = redactNetwork({ effectiveType: '3g', rtt: 123 }, pol);
  assert.equal(n.rtt, 100);
});

test('后台读取拒绝', () => {
  const g = new BatteryGuard();
  assert.equal(g.decideRead(ctx({ isBackground: true })).reason, BG_REASON.BACKGROUND_READ);
});

test('读取节流', () => {
  const g = new BatteryGuard();
  assert.equal(g.decideRead(ctx({ now: 0 })).allowed, true);
  assert.equal(g.decideRead(ctx({ now: 500 })).reason, BG_REASON.READ_THROTTLED);
  assert.equal(g.decideRead(ctx({ now: 1001 })).allowed, true);
});

test('监听器数量上限', () => {
  const g = new BatteryGuard();
  for (let i = 0; i < 4; i++) {
    assert.equal(g.decideAddListener(ctx({ now: i * 2001 })).allowed, true);
  }
  assert.equal(g.decideAddListener(ctx({ now: 9000 })).reason, BG_REASON.TOO_MANY_LISTENERS);
  g.noteRemoveListener(ORIGIN);
  assert.equal(g.decideAddListener(ctx({ now: 11000 })).allowed, true);
});

test('非法 origin 拒绝', () => {
  const g = new BatteryGuard();
  assert.equal(g.decideRead(ctx({ origin: 'file:///x' })).reason, BG_REASON.BAD_ORIGIN);
});
