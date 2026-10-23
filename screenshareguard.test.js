'use strict';

// screenshareguard.test.js —— 屏幕共享门、危险采集项、表面确认、时长上限。

const test = require('node:test');
const assert = require('node:assert/strict');
const ss = require('./screenshareguard');
const { ScreenshareGuard, SS_REASON, SURFACE, defaultScreensharePolicy } = ss;

const ORIGIN = 'https://meet.example.com';
function ctx(over) {
  return Object.assign({
    origin: ORIGIN, isSecureContext: true, hasUserGesture: true,
    isBackground: false, blocked: false, now: 1000,
  }, over || {});
}

test('非安全/后台/无手势拒绝', () => {
  const g = new ScreenshareGuard();
  assert.equal(g.decideRequest(ctx({ isSecureContext: false }), { video: {} }).reason, SS_REASON.INSECURE_CONTEXT);
  assert.equal(g.decideRequest(ctx({ isBackground: true }), { video: {} }).reason, SS_REASON.BACKGROUND_SHARE);
  assert.equal(g.decideRequest(ctx({ hasUserGesture: false }), { video: {} }).reason, SS_REASON.NO_GESTURE);
});

test('请求节流', () => {
  const g = new ScreenshareGuard();
  assert.equal(g.decideRequest(ctx({ now: 0 }), { video: {} }).decision, 'prompt');
  assert.equal(g.decideRequest(ctx({ now: 1000 }), { video: {} }).reason, SS_REASON.REQUEST_THROTTLED);
});

test('系统声音包含默认拒绝', () => {
  const g = new ScreenshareGuard();
  const r = g.decideRequest(ctx({ now: 0 }), { video: {}, audio: 'include' });
  assert.equal(r.reason, SS_REASON.SYSTEM_AUDIO_FORBIDDEN);
});

test('自身表面/动态切换/逻辑表面默认拒绝', () => {
  const g = new ScreenshareGuard();
  assert.equal(g.decideRequest(ctx({ now: 0 }), { video: { selfBrowserSurface: 'include' } }).reason, SS_REASON.SELF_SURFACE_FORBIDDEN);
  assert.equal(g.decideRequest(ctx({ now: 2100 }), { video: { surfaceSwitching: 'include' } }).reason, SS_REASON.SURFACE_SWITCH_FORBIDDEN);
  assert.equal(g.decideRequest(ctx({ now: 4200 }), { video: { logicalSurface: true } }).reason, SS_REASON.LOGICAL_SURFACE_FORBIDDEN);
});

test('抑制本地外放默认拒绝', () => {
  const g = new ScreenshareGuard();
  const r = g.decideRequest(ctx({ now: 0 }), { video: {}, suppressLocalAudioPlayback: true });
  assert.equal(r.reason, SS_REASON.SUPPRESS_AUDIO_PLAYBACK_FORBIDDEN);
});

test('干净请求放行并给出安全提示', () => {
  const g = new ScreenshareGuard();
  const r = g.decideRequest(ctx({ now: 0 }), { video: {} });
  assert.equal(r.decision, 'prompt');
  assert.equal(r.safeHints.selfBrowserSurface, 'exclude');
  assert.equal(r.safeHints.systemAudio, 'exclude');
  assert.equal(r.safeHints.monitorSurfacePicking, 'require-confirm');
});

test('monitor 表面需要二次确认；非法表面拒绝', () => {
  const g = new ScreenshareGuard();
  const mon = g.noteStarted(ORIGIN, SURFACE.MONITOR, 0);
  assert.equal(mon.ok, true);
  assert.equal(mon.reason, SS_REASON.MONITOR_SURFACE_REQUIRES_CONFIRM);
  const win = g.noteStarted(ORIGIN, SURFACE.WINDOW, 0);
  assert.equal(win.reason, '');
  assert.equal(g.noteStarted(ORIGIN, 'projector', 0).ok, false);
});

test('共享超最长时长自动停', () => {
  const pol = defaultScreensharePolicy();
  const g = new ScreenshareGuard(pol);
  g.noteStarted(ORIGIN, SURFACE.WINDOW, 0);
  assert.equal(g.checkStillAllowed(ORIGIN, 1000).active, true);
  const stop = g.checkStillAllowed(ORIGIN, pol.maxShareMs + 1);
  assert.equal(stop.stop, true);
  assert.equal(stop.reason, SS_REASON.MAX_DURATION_EXCEEDED);
  assert.equal(g.checkStillAllowed(ORIGIN, pol.maxShareMs + 2).active, false);
});

test('停止后不再活动', () => {
  const g = new ScreenshareGuard();
  g.noteStarted(ORIGIN, SURFACE.BROWSER, 0);
  g.noteStopped(ORIGIN);
  assert.equal(g.checkStillAllowed(ORIGIN, 100).active, false);
});
