'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const n = require('./notificationsourceprompt');

test('denied 直接 hide', () => {
  const r = n.decideNotificationDisplay({ permission: 'denied', hasUserGesture: true, titleLength: 10 });
  assert.equal(r.action, 'hide');
});

test('default 无手势 hide', () => {
  const r = n.decideNotificationDisplay({ permission: 'default', hasUserGesture: false, titleLength: 10 });
  assert.equal(r.action, 'hide');
});

test('granted 显示', () => {
  const r = n.decideNotificationDisplay({ permission: 'granted', hasUserGesture: false, titleLength: 10 });
  assert.equal(r.action, 'show');
});

test('未信任源强制带 origin 标注', () => {
  const r = n.decideNotificationDisplay({ permission: 'granted', titleLength: 10, userTrustedOrigin: false });
  assert.equal(r.annotateOrigin, true);
});

test('信任源不标注', () => {
  const r = n.decideNotificationDisplay({ permission: 'granted', titleLength: 10, userTrustedOrigin: true });
  assert.equal(r.annotateOrigin, false);
});

test('标题过长 hide', () => {
  const r = n.decideNotificationDisplay({ permission: 'granted', titleLength: 500 });
  assert.equal(r.action, 'hide');
});

test('重复通知折叠', () => {
  assert.equal(n.shouldSuppressRepeated(3), false);
  assert.equal(n.shouldSuppressRepeated(5), true);
  assert.equal(n.shouldSuppressRepeated(10), true);
});
