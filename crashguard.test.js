'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  CRASH_NOTIFY,
  CRASH_SUPPRESS,
  CRASH_DROP,
  SUPPRESS_LOOP,
  DROP_BAD_FIELD,
  CRASH_NOTIFY_GAP_MS,
  CRASH_MAX_SUPPRESSED,
  sanitizePluginCrash,
  crashKey,
  createCrashState,
  resetForNavigation,
  decidePluginCrash,
  describeCrashReason,
} = require('./crashguard');

const T0 = 30_000_000;

test('合法插件名/版本通过', () => {
  const r = sanitizePluginCrash('PDF Viewer', '12.4.1-rc_2');
  assert.equal(r.ok, true);
  assert.equal(r.name, 'PDF Viewer');
});

test('换行/ANSI/控制字符被剥离，非白名字符拒绝', () => {
  const injected = sanitizePluginCrash("PDF\r\nFAKE\x1b[31m", '1.0');
  assert.equal(injected.ok, false);
  const cleaned = sanitizePluginCrash('  Flash Player  ', '32.0');
  assert.equal(cleaned.name, 'Flash Player');
  for (const badName of ['evil/../x', 'name;rm', '<script>', '', 'a'.repeat(200)]) {
    assert.equal(sanitizePluginCrash(badName, '1.0').ok, false, badName);
  }
  for (const badVer of ['1 2', '1.0\n', '', 'v'.repeat(100)]) {
    assert.equal(sanitizePluginCrash('PDF', badVer).ok, false, badVer);
  }
});

test('非字符串字段拒绝', () => {
  assert.equal(sanitizePluginCrash(undefined, '1').ok, false);
  assert.equal(sanitizePluginCrash('PDF', null).ok, false);
});

test('同一插件时间窗内的重复崩溃被折叠，首次通知', () => {
  const st = createCrashState(T0);
  const first = decidePluginCrash(st, 'PDF', '1.0', T0);
  assert.equal(first.action, CRASH_NOTIFY);
  assert.equal(first.suppressedSinceLastNotify, 0);
  const second = decidePluginCrash(st, 'PDF', '1.0', T0 + 1_000);
  assert.equal(second.action, CRASH_SUPPRESS);
  assert.equal(second.reason, SUPPRESS_LOOP);
  assert.equal(second.suppressedSinceLastNotify, 1);
  const third = decidePluginCrash(st, 'PDF', '1.0', T0 + 2_000);
  assert.equal(third.action, CRASH_SUPPRESS);
  assert.equal(third.suppressedSinceLastNotify, 2);
});

test('不同插件分别通知、分别计数', () => {
  const st = createCrashState(T0);
  assert.equal(decidePluginCrash(st, 'PDF', '1.0', T0).action, CRASH_NOTIFY);
  assert.equal(decidePluginCrash(st, 'Pepper', '2.0', T0 + 100).action, CRASH_NOTIFY);
  assert.equal(decidePluginCrash(st, 'PDF', '1.0', T0 + 200).action, CRASH_SUPPRESS);
  assert.equal(st.plugins.size, 2);
});

test('超过通知时间窗后再次通知并返回折叠数', () => {
  const st = createCrashState(T0);
  decidePluginCrash(st, 'PDF', '1.0', T0);
  decidePluginCrash(st, 'PDF', '1.0', T0 + 1_000);
  decidePluginCrash(st, 'PDF', '1.0', T0 + 2_000);
  const flush = decidePluginCrash(st, 'PDF', '1.0', T0 + CRASH_NOTIFY_GAP_MS + 1);
  assert.equal(flush.action, CRASH_NOTIFY);
  assert.equal(flush.suppressedSinceLastNotify, 2);
  // 汇总后折叠计数清零。
  const again = decidePluginCrash(st, 'PDF', '1.0', T0 + CRASH_NOTIFY_GAP_MS + 2_000);
  assert.equal(again.action, CRASH_SUPPRESS);
  assert.equal(again.suppressedSinceLastNotify, 1);
});

test('折叠上限到达后强制再汇总，计数器不无限增长', () => {
  const st = createCrashState(T0);
  decidePluginCrash(st, 'PDF', '1.0', T0);
  let last;
  for (let i = 0; i < CRASH_MAX_SUPPRESSED + 1; i++) {
    last = decidePluginCrash(st, 'PDF', '1.0', T0 + i + 1);
  }
  assert.equal(last.action, CRASH_NOTIFY);
  assert.equal(last.suppressedSinceLastNotify, CRASH_MAX_SUPPRESSED);
});

test('字段非法的崩溃事件被丢弃且不建立计数', () => {
  const st = createCrashState(T0);
  const r = decidePluginCrash(st, 'bad\nname', '1', T0);
  assert.equal(r.action, CRASH_DROP);
  assert.equal(r.reason, DROP_BAD_FIELD);
  assert.equal(st.plugins.size, 0);
});

test('主导航重置折叠状态', () => {
  const st = createCrashState(T0);
  decidePluginCrash(st, 'PDF', '1.0', T0);
  decidePluginCrash(st, 'PDF', '1.0', T0 + 100);
  resetForNavigation(st);
  const r = decidePluginCrash(st, 'PDF', '1.0', T0 + 200);
  assert.equal(r.action, CRASH_NOTIFY);
  assert.equal(r.suppressedSinceLastNotify, 0);
});

test('key 稳定且描述可读', () => {
  assert.equal(crashKey('PDF', '1.0'), 'PDF@1.0');
  for (const reason of [SUPPRESS_LOOP, DROP_BAD_FIELD]) {
    assert.ok(describeCrashReason(reason).length > 0);
  }
});
