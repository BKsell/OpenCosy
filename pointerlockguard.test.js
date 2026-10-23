'use strict';

// pointerlockguard.test.js —— 手势门、目标可见/尺寸/遮挡、退出冷却、自动重入节流。

const test = require('node:test');
const assert = require('node:assert/strict');
const { PointerLockGuard, PL_ALLOW, PL_DENY, PL_PROMPT } = require('./pointerlockguard');

const ctx = (over) => Object.assign({
  origin: 'https://game.example.com',
  isSecureContext: true,
  hasUserGesture: true,
  isBackground: false,
  isTopFrame: true,
  isFullscreen: false,
  blocked: false,
  now: 1000,
}, over || {});

const target = (over) => Object.assign({
  visible: true, width: 800, height: 600, opacity: 1,
  obscuredByOverlay: false, isTopmostElement: true,
}, over || {});

test('正常可见目标 + 手势允许', () => {
  const g = new PointerLockGuard();
  assert.equal(g.decideRequest(ctx(), target()).decision, PL_ALLOW);
});

test('非安全上下文拒绝', () => {
  const g = new PointerLockGuard();
  assert.equal(g.decideRequest(ctx({ isSecureContext: false, origin: 'http://g.com' }), target()).reason, 'pl-insecure-context');
});

test('坏 origin 拒绝', () => {
  const g = new PointerLockGuard();
  assert.equal(g.decideRequest(ctx({ origin: 'x' }), target()).decision, PL_DENY);
});

test('无手势首次走自动重入额度', () => {
  const g = new PointerLockGuard();
  const r = g.decideRequest(ctx({ hasUserGesture: false }), target());
  assert.equal(r.decision, PL_ALLOW);
  assert.equal(r.autoReentry, true);
});

test('自动重入超额后无手势拒绝', () => {
  const g = new PointerLockGuard();
  g.decideRequest(ctx({ hasUserGesture: false, now: 0 }), target());
  // 第二次超过间隔，用掉最后一次自动重入额度
  g.decideRequest(ctx({ hasUserGesture: false, now: 5000 }), target());
  const r = g.decideRequest(ctx({ hasUserGesture: false, now: 10000 }), target());
  assert.equal(r.reason, 'pl-no-user-gesture');
});

test('快速重复请求节流', () => {
  const g = new PointerLockGuard();
  g.decideRequest(ctx({ now: 0 }), target());
  const r = g.decideRequest(ctx({ now: 100 }), target());
  assert.equal(r.decision, PL_PROMPT);
});

test('透明/隐藏目标拒绝', () => {
  const g = new PointerLockGuard();
  assert.equal(g.decideRequest(ctx(), target({ opacity: 0 })).reason, 'pl-target-not-visible');
  assert.equal(g.decideRequest(ctx(), target({ visible: false })).reason, 'pl-target-not-visible');
});

test('过小目标拒绝', () => {
  const g = new PointerLockGuard();
  assert.equal(g.decideRequest(ctx(), target({ width: 10, height: 10 })).reason, 'pl-target-too-small');
});

test('被遮挡目标拒绝', () => {
  const g = new PointerLockGuard();
  assert.equal(g.decideRequest(ctx(), target({ obscuredByOverlay: true })).reason, 'pl-target-obscured');
  assert.equal(g.decideRequest(ctx(), target({ isTopmostElement: false })).reason, 'pl-target-obscured');
});

test('后台/iframe 拒绝', () => {
  const g = new PointerLockGuard();
  assert.equal(g.decideRequest(ctx({ isBackground: true }), target()).reason, 'pl-background-tab');
  assert.equal(g.decideRequest(ctx({ isTopFrame: false }), target()).reason, 'pl-untrusted-frame');
});

test('要求全屏策略下非全屏拒绝', () => {
  const g = new PointerLockGuard();
  g.policy.requireFullscreen = true;
  assert.equal(g.decideRequest(ctx(), target()).reason, 'pl-requires-fullscreen');
  assert.equal(g.decideRequest(ctx({ isFullscreen: true }), target()).decision, PL_ALLOW);
});

test('用户退出冷却期内拒绝', () => {
  const g = new PointerLockGuard();
  g.noteUserExit(ctx().origin, 1000);
  const r = g.decideRequest(ctx({ now: 1500 }), target());
  assert.equal(r.reason, 'pl-cooldown-after-user-exit');
  assert.equal(g.decideRequest(ctx({ now: 4000 }), target()).decision, PL_ALLOW);
});

test('程序自身退出不施加冷却', () => {
  const g = new PointerLockGuard();
  g.decideRequest(ctx({ now: 0 }), target());
  g.programmaticExit(ctx().origin);
  // 但重请求节流仍在；等到间隔后应允许
  assert.equal(g.decideRequest(ctx({ now: 2000 }), target()).decision, PL_ALLOW);
});

test('被封禁来源拒绝', () => {
  const g = new PointerLockGuard();
  assert.equal(g.decideRequest(ctx({ blocked: true }), target()).reason, 'pl-origin-blocked');
});

test('空上下文拒绝', () => {
  const g = new PointerLockGuard();
  assert.equal(g.decideRequest(null, target()).decision, PL_DENY);
});
