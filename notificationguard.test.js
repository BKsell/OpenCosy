'use strict';

// notificationguard.test.js —— 权限申请、频控、静默时段、伪造来源、图标信标、点击导航。

const test = require('node:test');
const assert = require('node:assert/strict');
const ng = require('./notificationguard');
const {
  NotificationGuard, N_REASON, defaultNotificationPolicy,
  originKey, parseUrlScheme, containsControlChar, stripControlChars, textClaimsForeignDomain,
} = ng;

const ORIGIN = 'https://mail.example.com';
function permCtx(over) {
  return Object.assign({
    origin: ORIGIN, isSecureContext: true, hasUserGesture: true,
    isBackground: false, blocked: false, now: 100000,
  }, over || {});
}

test('originKey 归一化与拒绝', () => {
  assert.equal(originKey('https://X.Example.com'), 'https://x.example.com');
  assert.equal(originKey('https://x.example.com/with/path'), '');
  assert.equal(originKey('ftp://x.com'), '');
  assert.equal(originKey('not a url'), '');
});

test('parseUrlScheme 纯字符判定', () => {
  assert.equal(parseUrlScheme('JavaScript:alert(1)'), 'javascript');
  assert.equal(parseUrlScheme('HTTPS://x'), 'https');
  assert.equal(parseUrlScheme('/path'), '');
});

test('控制字符检测与剥离', () => {
  assert.ok(containsControlChar('a\x00b'));
  assert.ok(!containsControlChar('a b\nc\td'));
  assert.equal(stripControlChars('a\x00b\x07c'), 'abc');
});

test('伪造来源域名检测', () => {
  assert.equal(textClaimsForeignDomain('登录 accounts.google.com', ORIGIN, ['google.com', 'microsoft.com']), 'google.com');
  assert.equal(textClaimsForeignDomain('mail.example.com 通知', ORIGIN, ['example.com']), '');
});

test('非安全上下文拒绝申请', () => {
  const g = new NotificationGuard();
  assert.equal(g.decidePermission(permCtx({ isSecureContext: false })).reason, N_REASON.INSECURE_CONTEXT);
});

test('无手势拒绝申请', () => {
  const g = new NotificationGuard();
  assert.equal(g.decidePermission(permCtx({ hasUserGesture: false })).reason, N_REASON.NO_GESTURE_PERMISSION);
});

test('后台拒绝申请', () => {
  const g = new NotificationGuard();
  assert.equal(g.decidePermission(permCtx({ isBackground: true })).reason, N_REASON.BACKGROUND_REQUEST);
});

test('申请弹窗节流', () => {
  const g = new NotificationGuard();
  assert.equal(g.decidePermission(permCtx({ now: 0 })).decision, 'prompt');
  assert.equal(g.decidePermission(permCtx({ now: 30000 })).reason, N_REASON.PERMISSION_THROTTLED);
  assert.equal(g.decidePermission(permCtx({ now: 60001 })).decision, 'prompt');
});

test('被拒冷却期内不再弹窗', () => {
  const g = new NotificationGuard();
  g.markDenied(ORIGIN, 0);
  assert.equal(g.decidePermission(permCtx({ now: 1000 })).reason, N_REASON.PERMISSION_DENIED);
});

test('未授权不能弹通知', () => {
  const g = new NotificationGuard();
  const r = g.decideNotification({ origin: ORIGIN, now: 0, hourOfDay: 12 }, { title: 'hi', body: '' });
  assert.equal(r.allowed, false);
  assert.equal(r.reason, N_REASON.PERMISSION_DENIED);
});

test('授权后正常弹，频控生效', () => {
  const g = new NotificationGuard();
  g.markGranted(ORIGIN);
  for (let i = 0; i < 6; i++) {
    const r = g.decideNotification({ origin: ORIGIN, now: i * 1000, hourOfDay: 12 }, { title: 't', body: 'b' });
    assert.equal(r.allowed, true);
  }
  const over = g.decideNotification({ origin: ORIGIN, now: 5500, hourOfDay: 12 }, { title: 't', body: 'b' });
  assert.equal(over.allowed, false);
  assert.equal(over.reason, N_REASON.FREQUENCY_EXCEEDED);
});

test('静默时段拦截', () => {
  const g = new NotificationGuard();
  g.markGranted(ORIGIN);
  const r = g.decideNotification({ origin: ORIGIN, now: 0, hourOfDay: 23 }, { title: 't', body: 'b' });
  assert.equal(r.reason, N_REASON.QUIET_HOURS);
});

test('控制字符内容拦截并净化', () => {
  const g = new NotificationGuard();
  g.markGranted(ORIGIN);
  const bad = g.decideNotification({ origin: ORIGIN, now: 0, hourOfDay: 12 }, { title: 'a\x00', body: 'b' });
  assert.equal(bad.reason, N_REASON.CONTROL_CHAR_IN_TEXT);
  const ok = g.decideNotification({ origin: ORIGIN, now: 90000, hourOfDay: 12 }, { title: 'a\tb', body: 'c' });
  assert.equal(ok.safeTitle, 'a\tb');
});

test('文案冒充品牌域拦截', () => {
  const g = new NotificationGuard();
  g.markGranted(ORIGIN);
  const r = g.decideNotification(
    { origin: ORIGIN, now: 0, hourOfDay: 12 },
    { title: '你的 Microsoft 账户异常', body: '' },
    ['microsoft', 'google.com'],
  );
  assert.equal(r.reason, N_REASON.SPOOFED_SOURCE);
});

test('非 https 图标拒绝，追踪主机拒绝', () => {
  const pol = defaultNotificationPolicy();
  pol.blockKnownTrackerHosts = ['tracker.evil.com'];
  const g = new NotificationGuard(pol);
  g.markGranted(ORIGIN);
  const r1 = g.decideNotification({ origin: ORIGIN, now: 0, hourOfDay: 12 }, { title: 't', body: '', iconUrl: 'http://x.com/i.png' });
  assert.equal(r1.reason, N_REASON.ICON_DISALLOWED_SCHEME);
  const r2 = g.decideNotification({ origin: ORIGIN, now: 61000, hourOfDay: 12 }, { title: 't', body: '', iconUrl: 'https://tracker.evil.com/p.gif' });
  assert.equal(r2.reason, N_REASON.ICON_THIRD_PARTY_TRACKER);
});

test('点击导航：危险 scheme 拒绝，跨跳标记 noopener', () => {
  const g = new NotificationGuard();
  assert.equal(g.decideClickNavigation(ORIGIN, 'javascript:alert(1)').allowed, false);
  const cross = g.decideClickNavigation(ORIGIN, 'https://login.evil.com/x');
  assert.equal(cross.allowed, true);
  assert.equal(cross.crossOrigin, true);
  assert.equal(cross.noopener, true);
  const same = g.decideClickNavigation(ORIGIN, 'https://mail.example.com/inbox');
  assert.equal(same.crossOrigin, false);
});
