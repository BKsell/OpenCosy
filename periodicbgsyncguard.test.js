'use strict';

// periodicbgsyncguard.test.js —— 周期后台同步安装态/权限/间隔/tag 上限，后台抓取体积与并发，撤销失效。

const test = require('node:test');
const assert = require('node:assert/strict');
const pb = require('./periodicbgsyncguard');
const { PeriodicBgSyncGuard, PB_REASON, defaultPeriodicBgPolicy } = pb;

function grantedCtx(over) {
  return Object.assign({
    origin: 'https://mail.example.com', isSecureContext: true, blocked: false,
    isInstalled: true,
  }, over || {});
}

function grantedGuard() {
  const pol = defaultPeriodicBgPolicy();
  pol.permissionGranted = true;
  return new PeriodicBgSyncGuard(pol);
}

test('非安全上下文拒绝', () => {
  const g = grantedGuard();
  assert.equal(g.decideRegisterPeriodic(grantedCtx({ isSecureContext: false }), 'sync', {}).reason, PB_REASON.INSECURE_CONTEXT);
});

test('未安装拒绝周期同步', () => {
  const g = grantedGuard();
  assert.equal(g.decideRegisterPeriodic(grantedCtx({ isInstalled: false }), 'sync', {}).reason, PB_REASON.NOT_INSTALLED);
});

test('默认未授权限拒绝', () => {
  const g = new PeriodicBgSyncGuard();
  assert.equal(g.decideRegisterPeriodic(grantedCtx(), 'sync', {}).reason, PB_REASON.PERMISSION_NOT_GRANTED);
});

test('间隔过小拒绝', () => {
  const g = grantedGuard();
  assert.equal(g.decideRegisterPeriodic(grantedCtx(), 'sync', { minInterval: 60000 }).reason, PB_REASON.INTERVAL_TOO_SMALL);
});

test('合法注册并取有效间隔', () => {
  const g = grantedGuard();
  const r = g.decideRegisterPeriodic(grantedCtx(), 'news', { minInterval: 24 * 60 * 60000 });
  assert.equal(r.allowed, true);
  assert.equal(r.effectiveIntervalMs, 24 * 60 * 60000);
});

test('重复 tag 拒绝', () => {
  const g = grantedGuard();
  g.decideRegisterPeriodic(grantedCtx(), 'news', {});
  assert.equal(g.decideRegisterPeriodic(grantedCtx(), 'news', {}).reason, PB_REASON.TAG_ALREADY_REGISTERED);
});

test('每来源 tag 上限', () => {
  const g = grantedGuard();
  g.decideRegisterPeriodic(grantedCtx(), 'a', {});
  assert.equal(g.decideRegisterPeriodic(grantedCtx(), 'b', {}).reason, PB_REASON.TOO_MANY_TAGS);
});

test('unregister 后可重新注册；revokeAll 清空', () => {
  const g = grantedGuard();
  g.decideRegisterPeriodic(grantedCtx(), 'a', {});
  g.unregister('https://mail.example.com', 'a');
  assert.equal(g.decideRegisterPeriodic(grantedCtx(), 'a', {}).allowed, true);
  g.revokeAll('https://mail.example.com');
  assert.equal(g.periodicTagCount('https://mail.example.com'), 0);
});

test('后台抓取超大拒绝', () => {
  const g = grantedGuard();
  const big = 51 * 1024 * 1024;
  assert.equal(g.decideBackgroundFetch(grantedCtx(), big).reason, PB_REASON.BG_FETCH_TOO_LARGE);
});

test('后台抓取并发上限', () => {
  const g = grantedGuard();
  assert.equal(g.decideBackgroundFetch(grantedCtx(), 1024).allowed, true);
  assert.equal(g.decideBackgroundFetch(grantedCtx(), 1024).reason, PB_REASON.TOO_MANY_BG_FETCH);
  g.noteBackgroundFetchDone('https://mail.example.com');
  assert.equal(g.decideBackgroundFetch(grantedCtx(), 1024).allowed, true);
});
