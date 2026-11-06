'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const guard = require('./pointerlockframe');

const SITE = 'https://game.test/play';

test('顶层活跃标签允许指针锁定', () => {
  const decision = guard.evaluatePointerLockFrame({ requestUrl: SITE, topUrl: SITE });
  assert.equal(decision.action, 'allow');
  assert.equal(decision.reason, 'ok');
});

test('跨源子框架被拒绝', () => {
  const decision = guard.evaluatePointerLockFrame({
    requestUrl: 'https://ads.test/frame',
    topUrl: SITE,
    isMainFrame: false,
  });
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'cross-origin-frame');
});

test('同源子框架允许，但受标签活跃状态约束', () => {
  const sameOrigin = guard.evaluatePointerLockFrame({
    requestUrl: 'https://game.test/frame',
    topUrl: SITE,
    isMainFrame: false,
  });
  assert.equal(sameOrigin.action, 'allow');
  const inactive = guard.evaluatePointerLockFrame({
    requestUrl: 'https://game.test/frame',
    topUrl: SITE,
    isMainFrame: false,
    tabActive: false,
  });
  assert.equal(inactive.action, 'deny');
  assert.equal(inactive.reason, 'tab-inactive');
});

test('失焦窗口拒绝，避免后台劫持鼠标', () => {
  const decision = guard.evaluatePointerLockFrame({ requestUrl: SITE, topUrl: SITE, windowFocused: false });
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'window-unfocused');
});

test('不透明 origin 拒绝', () => {
  const decision = guard.evaluatePointerLockFrame({ requestUrl: 'data:text/html,x', topUrl: SITE });
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'opaque-origin');
});

test('空 URL 拒绝', () => {
  const decision = guard.evaluatePointerLockFrame({ requestUrl: '', topUrl: SITE });
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'missing-url');
});

test('明文站点仅告警', () => {
  const decision = guard.evaluatePointerLockFrame({ requestUrl: 'http://game.test/', topUrl: 'http://game.test/' });
  assert.equal(decision.action, 'warn');
  assert.equal(decision.reason, 'insecure-transport');
});

test('describe 输出原因与细节', () => {
  const decision = guard.evaluatePointerLockFrame({ requestUrl: '', topUrl: SITE });
  assert.match(guard.describePointerLockFrame(decision), /missing-url/);
  assert.equal(guard.describePointerLockFrame({ action: 'allow', reason: 'ok' }), '指针锁定帧边界校验通过');
});
