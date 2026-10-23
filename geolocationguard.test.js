'use strict';

// geolocationguard.test.js —— 权限门、节流、后台/框架、高精度、watch 配额与坐标模糊。

const test = require('node:test');
const assert = require('node:assert/strict');
const g = require('./geolocationguard');
const { GeoPromptGate, blurCoordinate, applyDecisionToPosition, GEO_ALLOW_COARSE, GEO_ALLOW_FINE, GEO_DENY, GEO_PROMPT, defaultGeoPolicy } = g;

const ctx = (over) => Object.assign({
  origin: 'https://maps.example.com',
  isSecureContext: true,
  hasUserGesture: true,
  isBackground: false,
  isTopFrame: true,
  highAccuracy: false,
  blocked: false,
  now: 100_000,
}, over || {});

test('正常手势同源请求允许粗略定位', () => {
  const gate = new GeoPromptGate();
  const d = gate.decideRequest(ctx());
  assert.equal(d.decision, GEO_ALLOW_COARSE);
});

test('非安全上下文拒绝', () => {
  const gate = new GeoPromptGate();
  const d = gate.decideRequest(ctx({ isSecureContext: false, origin: 'http://maps.example.com' }));
  assert.equal(d.decision, GEO_DENY);
  assert.equal(d.reason, 'geo-insecure-context');
});

test('坏 origin 拒绝', () => {
  const gate = new GeoPromptGate();
  assert.equal(gate.decideRequest(ctx({ origin: 'garbage' })).decision, GEO_DENY);
});

test('无手势拒绝', () => {
  const gate = new GeoPromptGate();
  const d = gate.decideRequest(ctx({ hasUserGesture: false }));
  assert.equal(d.reason, 'geo-no-user-gesture');
});

test('后台标签拒绝', () => {
  const gate = new GeoPromptGate();
  const d = gate.decideRequest(ctx({ isBackground: true }));
  assert.equal(d.reason, 'geo-background-tab');
});

test('iframe 默认拒绝', () => {
  const gate = new GeoPromptGate();
  const d = gate.decideRequest(ctx({ isTopFrame: false }));
  assert.equal(d.reason, 'geo-untrusted-frame');
});

test('高精度请求转提示而非直接给', () => {
  const gate = new GeoPromptGate();
  const d = gate.decideRequest(ctx({ highAccuracy: true }));
  assert.equal(d.decision, GEO_PROMPT);
  assert.equal(d.reason, 'geo-high-accuracy-not-permitted');
});

test('用户明确授权后才给高精度', () => {
  const gate = new GeoPromptGate();
  const d = gate.grantFine(ctx());
  assert.equal(d.decision, GEO_ALLOW_FINE);
});

test('权限弹窗节流：窗口内重复请求转提示', () => {
  const gate = new GeoPromptGate();
  gate.decideRequest(ctx({ now: 1000 }));
  const d2 = gate.decideRequest(ctx({ now: 2000 }));
  assert.equal(d2.decision, GEO_PROMPT);
  assert.equal(d2.reason, 'geo-prompt-throttled');
});

test('超过节流窗口可再次允许', () => {
  const gate = new GeoPromptGate();
  gate.decideRequest(ctx({ now: 0 }));
  const d = gate.decideRequest(ctx({ now: 61_000 }));
  assert.equal(d.decision, GEO_ALLOW_COARSE);
});

test('被封禁来源拒绝', () => {
  const gate = new GeoPromptGate();
  assert.equal(gate.decideRequest(ctx({ blocked: true })).reason, 'geo-origin-blocked');
});

test('watch 会话数上限', () => {
  const gate = new GeoPromptGate();
  for (let i = 0; i < 3; i++) {
    assert.equal(gate.registerWatch(ctx(), 10_000).ok, true);
  }
  const r = gate.registerWatch(ctx(), 10_000);
  assert.equal(r.ok, false);
});

test('watch 间隔过小被抬到最小值', () => {
  const gate = new GeoPromptGate();
  const r = gate.registerWatch(ctx(), 10);
  assert.equal(r.intervalMs, defaultGeoPolicy().minWatchIntervalMs);
  gate.releaseWatch(ctx().origin);
});

test('releaseWatch 释放会话配额', () => {
  const gate = new GeoPromptGate();
  gate.registerWatch(ctx(), 10_000);
  gate.releaseWatch(ctx().origin);
  const r = gate.registerWatch(ctx(), 10_000);
  assert.equal(r.ok, true);
});

test('坐标模糊返回量化网格点', () => {
  const b = blurCoordinate(24.4798, 118.0894, 5000);
  assert.ok(b.blurred);
  assert.equal(b.accuracy, 5000);
  assert.ok(Math.abs(b.latitude - 24.4798) < 0.1);
  assert.notDeepEqual([b.latitude, b.longitude], [24.4798, 118.0894]);
});

test('非法坐标模糊返回 null', () => {
  assert.equal(blurCoordinate(200, 0, 5000), null);
  assert.equal(blurCoordinate(NaN, 0, 5000), null);
});

test('粗略裁决把高精度位置收敛为模糊点', () => {
  const pos = { latitude: 24.4798, longitude: 118.0894, accuracy: 10 };
  const out = applyDecisionToPosition(GEO_ALLOW_COARSE, pos);
  assert.equal(out.accuracy, 5000);
  assert.ok(out.blurred);
});

test('高精度裁决仍设精度下限', () => {
  const pos = { latitude: 24.4798, longitude: 118.0894, accuracy: 5 };
  const out = applyDecisionToPosition(GEO_ALLOW_FINE, pos);
  assert.ok(out.accuracy >= defaultGeoPolicy().fineAccuracyFloorMeters);
});

test('空上下文拒绝', () => {
  const gate = new GeoPromptGate();
  assert.equal(gate.decideRequest(null).decision, GEO_DENY);
});
