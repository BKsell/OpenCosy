'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const guard = require('./popupopenerframe');

const SITE = 'https://portal.test/home';

test('顶层活跃标签允许弹窗', () => {
  const decision = guard.evaluatePopupFrame({ requestUrl: SITE, topUrl: SITE });
  assert.equal(decision.action, 'allow');
  assert.equal(decision.reason, 'ok');
});

test('跨源 iframe 弹窗被拒绝', () => {
  const decision = guard.evaluatePopupFrame({
    requestUrl: 'https://ads.test/frame',
    topUrl: SITE,
    isMainFrame: false,
  });
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'cross-origin-frame');
});

test('同源 iframe 允许弹窗', () => {
  const decision = guard.evaluatePopupFrame({
    requestUrl: 'https://portal.test/widget',
    topUrl: SITE,
    isMainFrame: false,
  });
  assert.equal(decision.action, 'allow');
});

test('嵌套层数超限被拒绝', () => {
  const decision = guard.evaluatePopupFrame({
    requestUrl: SITE,
    topUrl: SITE,
    frameDepth: guard.MAX_POPUP_FRAME_DEPTH + 1,
  });
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'too-many-frames');
});

test('后台标签弹窗被拒绝', () => {
  const decision = guard.evaluatePopupFrame({ requestUrl: SITE, topUrl: SITE, tabActive: false });
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'tab-inactive');
});

test('失焦窗口弹窗被拒绝', () => {
  const decision = guard.evaluatePopupFrame({ requestUrl: SITE, topUrl: SITE, windowFocused: false });
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'window-unfocused');
});

test('不透明 origin 被拒绝', () => {
  const decision = guard.evaluatePopupFrame({ requestUrl: 'data:text/html,x', topUrl: SITE });
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'opaque-origin');
});

test('明文站点弹窗只告警', () => {
  const decision = guard.evaluatePopupFrame({
    requestUrl: 'http://portal.test/',
    topUrl: 'http://portal.test/',
  });
  assert.equal(decision.action, 'warn');
  assert.equal(decision.reason, 'insecure-transport');
});

test('describe 文案', () => {
  assert.equal(guard.describePopupFrame({ reason: 'ok' }), '弹窗帧边界校验通过');
  assert.match(guard.describePopupFrame({ reason: 'cross-origin-frame', detail: 'x' }), /cross-origin-frame/);
});
