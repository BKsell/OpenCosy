'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const guard = require('./fullscreenframe');

const SITE = 'https://video.test/watch';

test('顶层活跃标签允许全屏', () => {
  const decision = guard.evaluateFullscreenFrame({ requestUrl: SITE, topUrl: SITE });
  assert.equal(decision.action, 'allow');
  assert.equal(decision.reason, 'ok');
});

test('跨源 iframe 全屏被拒绝', () => {
  const decision = guard.evaluateFullscreenFrame({
    requestUrl: 'https://ads.test/frame',
    topUrl: SITE,
    isMainFrame: false,
  });
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'cross-origin-frame');
});

test('后台标签全屏被拒绝', () => {
  const decision = guard.evaluateFullscreenFrame({ requestUrl: SITE, topUrl: SITE, tabActive: false });
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'tab-inactive');
});

test('失焦窗口全屏被拒绝', () => {
  const decision = guard.evaluateFullscreenFrame({ requestUrl: SITE, topUrl: SITE, windowFocused: false });
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'window-unfocused');
});

test('键盘锁请求只告警', () => {
  const decision = guard.evaluateFullscreenFrame({ requestUrl: SITE, topUrl: SITE, keyboardLock: true });
  assert.equal(decision.action, 'warn');
  assert.equal(decision.reason, 'keyboard-lock');
});

test('明文全屏只告警', () => {
  const decision = guard.evaluateFullscreenFrame({
    requestUrl: 'http://video.test/',
    topUrl: 'http://video.test/',
  });
  assert.equal(decision.action, 'warn');
  assert.equal(decision.reason, 'insecure-transport');
});

test('空 URL 拒绝', () => {
  const decision = guard.evaluateFullscreenFrame({ requestUrl: '', topUrl: SITE });
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'missing-url');
});

test('describe 兜底文案', () => {
  assert.equal(guard.describeFullscreenFrame(null), '全屏帧边界校验通过');
  assert.match(guard.describeFullscreenFrame({ reason: 'tab-inactive', detail: 'x' }), /tab-inactive/);
});
