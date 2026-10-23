'use strict';

// keyboardlockguard.test.js —— 全捕获拒绝、禁用键、白名单、手势/全屏门、节流。

const test = require('node:test');
const assert = require('node:assert/strict');
const { KeyboardLockGuard, KL_ALLOW, KL_DENY, KL_PROMPT } = require('./keyboardlockguard');

const ctx = (over) => Object.assign({
  origin: 'https://game.example.com',
  isSecureContext: true,
  hasUserGesture: true,
  isBackground: false,
  isTopFrame: true,
  isFullscreen: true,
  blocked: false,
  now: 1000,
}, over || {});

test('显式游戏键 + 全屏 + 手势允许', () => {
  const g = new KeyboardLockGuard();
  const r = g.decideLock(ctx(), ['KeyW', 'KeyA', 'Space', 'ArrowUp']);
  assert.equal(r.decision, KL_ALLOW);
  assert.equal(r.keys.length, 4);
});

test('空数组=全捕获必须拒绝', () => {
  const g = new KeyboardLockGuard();
  assert.equal(g.decideLock(ctx(), []).reason, 'kl-empty-means-capture-all');
  assert.equal(g.decideLock(ctx()).reason, 'kl-empty-means-capture-all');
});

test('禁用系统键拒绝', () => {
  const g = new KeyboardLockGuard();
  assert.equal(g.decideLock(ctx(), ['Escape']).reason, 'kl-forbidden-key');
  assert.equal(g.decideLock(ctx(), ['Tab']).reason, 'kl-forbidden-key');
  assert.equal(g.decideLock(ctx(), ['MetaLeft']).reason, 'kl-forbidden-key');
  assert.equal(g.decideLock(ctx(), ['AltTab'.slice(0, 3) + 'Left']).reason, 'kl-forbidden-key');
});

test('未知键拒绝', () => {
  const g = new KeyboardLockGuard();
  assert.equal(g.decideLock(ctx(), ['BogusKey']).reason, 'kl-unknown-key');
  assert.equal(g.decideLock(ctx(), ['']).reason, 'kl-unknown-key');
});

test('重复键拒绝', () => {
  const g = new KeyboardLockGuard();
  assert.equal(g.decideLock(ctx(), ['KeyW', 'KeyW']).reason, 'kl-duplicate-key');
});

test('超量键拒绝', () => {
  const g = new KeyboardLockGuard();
  const many = ['KeyW', 'KeyA', 'KeyS', 'KeyD', 'KeyQ', 'KeyE', 'KeyR', 'KeyF',
    'Digit1', 'Digit2', 'Digit3', 'Digit4', 'Digit5', 'Digit6', 'Space', 'Enter', 'F4'];
  assert.equal(g.decideLock(ctx(), many).reason, 'kl-too-many-keys');
});

test('非全屏默认拒绝', () => {
  const g = new KeyboardLockGuard();
  assert.equal(g.decideLock(ctx({ isFullscreen: false }), ['KeyW']).reason, 'kl-requires-fullscreen');
});

test('无手势拒绝', () => {
  const g = new KeyboardLockGuard();
  assert.equal(g.decideLock(ctx({ hasUserGesture: false }), ['KeyW']).reason, 'kl-no-user-gesture');
});

test('非安全上下文拒绝', () => {
  const g = new KeyboardLockGuard();
  assert.equal(g.decideLock(ctx({ isSecureContext: false, origin: 'http://g.com' }), ['KeyW']).reason, 'kl-insecure-context');
});

test('后台/iframe 拒绝', () => {
  const g = new KeyboardLockGuard();
  assert.equal(g.decideLock(ctx({ isBackground: true }), ['KeyW']).reason, 'kl-background-tab');
  assert.equal(g.decideLock(ctx({ isTopFrame: false }), ['KeyW']).reason, 'kl-untrusted-frame');
});

test('重复请求节流', () => {
  const g = new KeyboardLockGuard();
  g.decideLock(ctx({ now: 0 }), ['KeyW']);
  assert.equal(g.decideLock(ctx({ now: 100 }), ['KeyW']).decision, KL_PROMPT);
});

test('放宽策略允许非全屏', () => {
  const g = new KeyboardLockGuard();
  g.policy.requireFullscreen = false;
  assert.equal(g.decideLock(ctx({ isFullscreen: false }), ['KeyW']).decision, KL_ALLOW);
});

test('被封禁来源拒绝', () => {
  const g = new KeyboardLockGuard();
  assert.equal(g.decideLock(ctx({ blocked: true }), ['KeyW']).reason, 'kl-origin-blocked');
});

test('空上下文拒绝', () => {
  const g = new KeyboardLockGuard();
  assert.equal(g.decideLock(null, ['KeyW']).decision, KL_DENY);
});
