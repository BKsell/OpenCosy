'use strict';

// idledetectguard.test.js —— 权限请求门、start 权限/后台/阈值/实例/节流、隐藏页外发、stop 回收。

const test = require('node:test');
const assert = require('node:assert/strict');
const id = require('./idledetectguard');
const { IdleDetectGuard, ID_REASON, defaultIdlePolicy } = id;

function ctx(over) {
  return Object.assign({
    origin: 'https://desk.example.com', isSecureContext: true, blocked: false,
    isBackground: false, isHidden: false, hasUserGesture: true, now: 0,
  }, over || {});
}

test('权限请求无手势拒绝', () => {
  const g = new IdleDetectGuard();
  assert.equal(g.decidePermissionRequest(ctx({ hasUserGesture: false })).reason, ID_REASON.NO_GESTURE_PERMISSION_REQUEST);
});

test('权限请求合法放行', () => {
  const g = new IdleDetectGuard();
  assert.equal(g.decidePermissionRequest(ctx()).allowed, true);
});

test('默认未授予权限时 start 拒绝', () => {
  const g = new IdleDetectGuard();
  assert.equal(g.decideStart(ctx(), { threshold: 60000 }).reason, ID_REASON.PERMISSION_NOT_GRANTED);
});

test('授予后合法 start', () => {
  const pol = defaultIdlePolicy();
  pol.permissionGranted = true;
  const g = new IdleDetectGuard(pol);
  const r = g.decideStart(ctx(), { threshold: 60000 });
  assert.equal(r.allowed, true);
  assert.equal(r.effectiveThresholdMs, 60000);
});

test('阈值过小拒绝', () => {
  const pol = defaultIdlePolicy();
  pol.permissionGranted = true;
  const g = new IdleDetectGuard(pol);
  assert.equal(g.decideStart(ctx(), { threshold: 1000 }).reason, ID_REASON.THRESHOLD_TOO_SMALL);
});

test('后台 start 拒绝', () => {
  const pol = defaultIdlePolicy();
  pol.permissionGranted = true;
  const g = new IdleDetectGuard(pol);
  assert.equal(g.decideStart(ctx({ isBackground: true }), { threshold: 60000 }).reason, ID_REASON.BACKGROUND_FORBIDDEN);
});

test('每来源最多一个 detector', () => {
  const pol = defaultIdlePolicy();
  pol.permissionGranted = true;
  pol.startMinIntervalMs = 0;
  const g = new IdleDetectGuard(pol);
  assert.equal(g.decideStart(ctx({ now: 0 }), { threshold: 60000 }).allowed, true);
  assert.equal(g.decideStart(ctx({ now: 10000 }), { threshold: 60000 }).reason, ID_REASON.TOO_MANY_DETECTORS);
});

test('stop 后可再次 start', () => {
  const pol = defaultIdlePolicy();
  pol.permissionGranted = true;
  pol.startMinIntervalMs = 0;
  const g = new IdleDetectGuard(pol);
  g.decideStart(ctx({ now: 0 }), { threshold: 60000 });
  g.noteStop('https://desk.example.com');
  assert.equal(g.decideStart(ctx({ now: 10000 }), { threshold: 60000 }).allowed, true);
});

test('隐藏页签禁止外发空闲事件', () => {
  const pol = defaultIdlePolicy();
  pol.permissionGranted = true;
  const g = new IdleDetectGuard(pol);
  assert.equal(g.decideReport(ctx({ isHidden: true })).reason, ID_REASON.EXFIL_WHILE_HIDDEN);
  assert.equal(g.decideReport(ctx()).allowed, true);
});

test('非安全上下文拒绝', () => {
  const g = new IdleDetectGuard();
  assert.equal(g.decideStart(ctx({ isSecureContext: false }), {}).reason, ID_REASON.INSECURE_CONTEXT);
});
