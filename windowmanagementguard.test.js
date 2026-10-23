'use strict';

// windowmanagementguard.test.js —— Window Management：手势/三方/权限、label 指纹、屏幕数、跨屏全屏、离屏放置、后台监听。

const test = require('node:test');
const assert = require('node:assert/strict');
const w = require('./windowmanagementguard');
const { WindowManagementGuard, WM_REASON, defaultWindowManagementPolicy } = w;

function ctx(over) {
  return Object.assign({ origin: 'https://desk.example.com', userGesture: true, isTopFrame: true, visible: true }, over || {});
}
const screens = [{ isInternal: true, label: '', width: 1920, height: 1080 }];

test('合规枚举放行', () => {
  const g = new WindowManagementGuard();
  assert.equal(g.decideGetDetails(ctx(), screens).decision, 'allow');
});

test('无手势/三方拒绝', () => {
  const g = new WindowManagementGuard();
  assert.equal(g.decideGetDetails(ctx({ userGesture: false }), screens).reason, WM_REASON.NO_GESTURE);
  assert.equal(g.decideGetDetails(ctx({ isTopFrame: false }), screens).reason, WM_REASON.THIRD_PARTY);
});

test('未授权拒绝', () => {
  const pol = defaultWindowManagementPolicy();
  pol.permissionGranted = false;
  const g = new WindowManagementGuard(pol);
  assert.equal(g.decideGetDetails(ctx(), screens).reason, WM_REASON.PERMISSION_DENIED);
});

test('label 指纹默认拒绝', () => {
  const g = new WindowManagementGuard();
  assert.equal(g.decideGetDetails(ctx(), [{ isInternal: false, label: 'Dell U2723QE' }]).reason,
    WM_REASON.LABEL_FINGERPRINT);
});

test('屏幕数过多拒绝', () => {
  const g = new WindowManagementGuard();
  const many = [];
  for (let i = 0; i < 5; i++) many.push({ label: '' });
  assert.equal(g.decideGetDetails(ctx(), many).reason, WM_REASON.TOO_MANY_SCREENS);
});

test('跨外接屏全屏默认拒绝', () => {
  const g = new WindowManagementGuard();
  assert.equal(g.decideFullscreen(ctx(), { isInternal: false }).reason, WM_REASON.FULLSCREEN_OTHER_SCREEN);
  assert.equal(g.decideFullscreen(ctx(), { isInternal: true }).decision, 'allow');
});

test('离屏放置/屏幕索引越界拒绝', () => {
  const g = new WindowManagementGuard();
  assert.equal(g.decidePlaceWindow(ctx(), { withinVisible: false }, 2).reason, WM_REASON.PLACE_OFFSCREEN);
  assert.equal(g.decidePlaceWindow(ctx(), { screenIndex: 3 }, 2).reason, WM_REASON.PLACE_OFFSCREEN);
  assert.equal(g.decidePlaceWindow(ctx(), { screenIndex: 1, withinVisible: true }, 2).decision, 'allow');
});

test('后台监听 screenschange 拒绝', () => {
  const g = new WindowManagementGuard();
  assert.equal(g.decideWatch(ctx({ visible: false })).reason, WM_REASON.WATCH_IN_BACKGROUND);
  assert.equal(g.decideWatch(ctx()).decision, 'allow');
});

test('非 https 拒绝', () => {
  const g = new WindowManagementGuard();
  assert.equal(g.decideGetDetails({ origin: 'http://x' }, screens).reason, WM_REASON.INSECURE_ORIGIN);
});
