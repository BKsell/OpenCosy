'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const guard = require('./notificationframe');

const SITE = 'https://chat.test/room';

test('顶层活跃标签允许通知', () => {
  const decision = guard.evaluateNotificationFrame({ requestUrl: SITE, topUrl: SITE, tag: 'room-1' });
  assert.equal(decision.action, 'allow');
  assert.equal(decision.reason, 'ok');
});

test('跨源 iframe 通知被拒绝', () => {
  const decision = guard.evaluateNotificationFrame({
    requestUrl: 'https://ads.test/frame',
    topUrl: SITE,
    isMainFrame: false,
  });
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'cross-origin-frame');
});

test('后台标签通知被拒绝', () => {
  const decision = guard.evaluateNotificationFrame({ requestUrl: SITE, topUrl: SITE, tabActive: false });
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'tab-inactive');
});

test('tag 超长被拒绝', () => {
  const decision = guard.evaluateNotificationFrame({
    requestUrl: SITE,
    topUrl: SITE,
    tag: 'x'.repeat(guard.MAX_TAG_LENGTH + 1),
  });
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'bad-tag');
});

test('tag 含控制字符被拒绝', () => {
  const decision = guard.evaluateNotificationFrame({ requestUrl: SITE, topUrl: SITE, tag: 'a\u0007b' });
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'bad-tag');
});

test('合法 tag 通过格式校验', () => {
  const decision = guard.evaluateNotificationFrame({ requestUrl: SITE, topUrl: SITE, tag: 'Msg_1:ok' });
  assert.equal(decision.action, 'allow');
  assert.equal(decision.tag, 'Msg_1:ok');
});

test('明文站点仅告警', () => {
  const decision = guard.evaluateNotificationFrame({
    requestUrl: 'http://chat.test/',
    topUrl: 'http://chat.test/',
  });
  assert.equal(decision.action, 'warn');
  assert.equal(decision.reason, 'insecure-transport');
});

test('空 URL 被拒绝', () => {
  const decision = guard.evaluateNotificationFrame({ requestUrl: '', topUrl: SITE });
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'missing-url');
});

test('describe 文案', () => {
  assert.equal(guard.describeNotificationFrame({ reason: 'ok' }), '通知权限帧边界校验通过');
  assert.match(guard.describeNotificationFrame({ reason: 'bad-tag', detail: 'x' }), /bad-tag/);
});
