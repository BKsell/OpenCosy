'use strict';

// fullscreenphishguard.test.js —— 手势/焦点/后台门、子框架、隐藏导航 UI、指针锁叠加、节流、退出提示。

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('./fullscreenphishguard');
const { FullscreenPhishGuard, FP_REASON } = fs;

function ctx(over) {
  return Object.assign({
    origin: 'https://media.example.com', isSecureContext: true, blocked: false,
    hasUserGesture: true, hasFocus: true, isBackground: false, isTopFrame: true, now: 0,
  }, over || {});
}

test('合法进入全屏放行', () => {
  const g = new FullscreenPhishGuard();
  assert.equal(g.decideEnter(ctx(), {}).decision, 'allow');
});

test('非安全上下文拒绝', () => {
  const g = new FullscreenPhishGuard();
  assert.equal(g.decideEnter(ctx({ isSecureContext: false }), {}).reason, FP_REASON.INSECURE_CONTEXT);
});

test('无手势/失焦/后台拒绝', () => {
  const g = new FullscreenPhishGuard();
  assert.equal(g.decideEnter(ctx({ hasUserGesture: false }), {}).reason, FP_REASON.NO_GESTURE);
  assert.equal(g.decideEnter(ctx({ hasFocus: false }), {}).reason, FP_REASON.NOT_FOCUSED);
  assert.equal(g.decideEnter(ctx({ isBackground: true }), {}).reason, FP_REASON.BACKGROUND);
});

test('子框架默认拒绝', () => {
  const g = new FullscreenPhishGuard();
  assert.equal(g.decideEnter(ctx({ isTopFrame: false }), {}).reason, FP_REASON.SUBFRAME_NOT_ALLOWED);
});

test('navigationUI hide 默认拒绝', () => {
  const g = new FullscreenPhishGuard();
  assert.equal(g.decideEnter(ctx({ now: 0 }), { navigationUI: 'hide' }).reason, FP_REASON.NAV_UI_HIDE_FORBIDDEN);
});

test('全屏叠加指针锁默认拒绝', () => {
  const g = new FullscreenPhishGuard();
  assert.equal(g.decideEnter(ctx({ now: 0 }), {}, ).decision, 'allow');
  assert.equal(g.decideEnter(ctx({ now: 3000, alsoPointerLock: true }), {}).reason, FP_REASON.POINTER_LOCK_WITH_FULLSCREEN);
});

test('进入节流', () => {
  const g = new FullscreenPhishGuard();
  assert.equal(g.decideEnter(ctx({ now: 0 }), {}).decision, 'allow');
  assert.equal(g.decideEnter(ctx({ now: 500 }), {}).reason, FP_REASON.FULLSCREEN_THROTTLED);
});

test('开启子框架后放行', () => {
  const g = new FullscreenPhishGuard();
  g.policy.allowSubframe = true;
  assert.equal(g.decideEnter(ctx({ isTopFrame: false, now: 0 }), {}).decision, 'allow');
});

test('必须展示退出提示', () => {
  const g = new FullscreenPhishGuard();
  assert.equal(g.mustShowExitNotice(), true);
});

test('坏 origin 拒绝', () => {
  const g = new FullscreenPhishGuard();
  assert.equal(g.decideEnter({ origin: 'xxx', isSecureContext: true }, {}).reason, FP_REASON.BAD_ORIGIN);
});
