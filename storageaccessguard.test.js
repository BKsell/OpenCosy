'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  KIND_SESSION,
  KIND_CACHE,
  ACTION_OBSERVE,
  ACTION_REPORT,
  DEFAULT_MAX_ACCESS_PER_WINDOW,
  MAX_STORAGE_BUCKETS,
  originFromUrl,
  clampToken,
  normalizeKind,
  bucketKey,
  createStorageAccessState,
  decideStorageAccess,
  summarizeKey,
} = require('./storageaccessguard');

test('normalizeKind / originFromUrl', () => {
  assert.equal(normalizeKind(KIND_SESSION), KIND_SESSION);
  assert.equal(normalizeKind(KIND_CACHE), KIND_CACHE);
  assert.equal(normalizeKind('cookie'), '');
  assert.equal(originFromUrl('https://a.test/x'), 'https://a.test');
  assert.equal(originFromUrl('bad'), '');
});

test('clampToken 去折行限长', () => {
  assert.equal(clampToken('a\nb', 10), 'a b');
  assert.equal(clampToken(undefined, 10), '');
  assert.equal(clampToken('abcdef', 4), 'abcd');
});

test('bucketKey 分桶包含类别/双源/类型', () => {
  const k = bucketKey(KIND_SESSION, 'https://t.ad', 'https://top.test', 'indexdb');
  assert.match(k, /^session-storage\|/);
  assert.ok(k.includes('https://t.ad'));
  assert.ok(k.includes('https://top.test'));
  assert.ok(k.endsWith('|indexdb'));
  assert.notEqual(
    bucketKey(KIND_SESSION, 'a', 'b', 'x'),
    bucketKey(KIND_CACHE, 'a', 'b', 'x'),
  );
});

test('同源访问常规观察，不上报', () => {
  const st = createStorageAccessState();
  const input = { kind: KIND_SESSION, frameUrl: 'https://a.test', topUrl: 'https://a.test', storageType: 'ls' };
  for (let i = 0; i < 10; i++) {
    const r = decideStorageAccess(st, input, i, { maxPerWindow: 100 });
    assert.equal(r.action, ACTION_OBSERVE);
    assert.equal(r.crossOrigin, false);
  }
  assert.equal(st.reports, 0);
});

test('跨源子框架首次访问上报一次，之后不再刷', () => {
  const st = createStorageAccessState();
  const input = {
    kind: KIND_SESSION,
    frameUrl: 'https://tracker.ad/frame',
    topUrl: 'https://news.test/',
    storageType: 'local storage',
  };
  const r1 = decideStorageAccess(st, input, 0);
  assert.equal(r1.action, ACTION_REPORT);
  assert.equal(r1.reason, 'cross-origin-storage-access');
  assert.equal(r1.crossOrigin, true);
  const r2 = decideStorageAccess(st, input, 5);
  assert.equal(r2.action, ACTION_OBSERVE);
  const r3 = decideStorageAccess(st, input, 9);
  assert.equal(r3.action, ACTION_OBSERVE);
  assert.equal(st.reports, 1);
});

test('不同跨源桶各自首次上报', () => {
  const st = createStorageAccessState();
  const a = decideStorageAccess(st, { kind: KIND_CACHE, frameUrl: 'https://x.ad', topUrl: 'https://top.test' }, 0);
  const b = decideStorageAccess(st, { kind: KIND_CACHE, frameUrl: 'https://y.ad', topUrl: 'https://top.test' }, 1);
  assert.equal(a.action, ACTION_REPORT);
  assert.equal(b.action, ACTION_REPORT);
});

test('高频洪泛：窗内超阈值升级且按窗限频', () => {
  const st = createStorageAccessState();
  const input = { kind: KIND_SESSION, frameUrl: 'https://a.test', topUrl: 'https://a.test' };
  let floodReports = 0;
  // maxPerWindow=5，窗口 1000ms
  for (let i = 0; i < 8; i++) {
    const r = decideStorageAccess(st, input, 10, { windowMs: 1000, maxPerWindow: 5 });
    if (r.action === ACTION_REPORT && r.reason === 'storage-access-flood') floodReports++;
  }
  assert.ok(floodReports >= 1, '应至少升级一次洪泛');
  // 同一窗口内重复洪泛被限频，不会每次都报
  assert.ok(floodReports <= 2);
});

test('滚动窗口过后可再次升级洪泛', () => {
  const st = createStorageAccessState();
  const input = { kind: KIND_CACHE, frameUrl: 'https://a.test', topUrl: 'https://a.test' };
  const opts = { windowMs: 1000, maxPerWindow: 4 };
  // 先打 4 次，恰好等于阈值，不越界
  for (let i = 0; i < 4; i++) assert.equal(decideStorageAccess(st, input, 0, opts).action, ACTION_OBSERVE);
  // 第 5 次越界 -> 洪泛上报
  const flood1 = decideStorageAccess(st, input, 10, opts);
  assert.equal(flood1.action, ACTION_REPORT);
  assert.equal(flood1.reason, 'storage-access-flood');
  // 进入新窗口，打满阈值后再越界，应能再次上报（距上次已超过一个窗）
  for (let i = 0; i < 4; i++) decideStorageAccess(st, input, 2000, opts);
  const flood2 = decideStorageAccess(st, input, 2001, opts);
  assert.equal(flood2.action, ACTION_REPORT);
  assert.equal(flood2.reason, 'storage-access-flood');
});

test('now<0 哨兵：不做窗口计数与洪泛升级', () => {
  const st = createStorageAccessState();
  const input = { kind: KIND_SESSION, frameUrl: 'https://a.test', topUrl: 'https://a.test' };
  for (let i = 0; i < 1000; i++) {
    const r = decideStorageAccess(st, input, -1);
    assert.equal(r.action, ACTION_OBSERVE);
    assert.equal(r.windowHits, 0);
  }
  assert.equal(st.reports, 0);
});

test('跨源判定在缺失任一源时不成立', () => {
  const st = createStorageAccessState();
  const r = decideStorageAccess(st, { kind: KIND_SESSION, frameUrl: 'bad', topUrl: 'https://a.test' }, 0);
  assert.equal(r.crossOrigin, false);
  assert.equal(r.action, ACTION_OBSERVE);
});

test('未知类别安全归一不抛异常', () => {
  const st = createStorageAccessState();
  const r = decideStorageAccess(st, { kind: 'weird' }, 0);
  assert.equal(r.kind, '');
  assert.equal(r.action, ACTION_OBSERVE);
  assert.equal(r.reason, 'unknown-kind');
});

test('缺入参不抛异常', () => {
  const r = decideStorageAccess(null, null, -1);
  assert.equal(r.action, ACTION_OBSERVE);
  assert.equal(createStorageAccessState().reports, 0);
});

test('summarizeKey 仅给长度与短前缀，不回传完整键', () => {
  const s = summarizeKey('session-key-secret-value');
  assert.equal(s.length, 24);
  assert.equal(s.head, 'session-');
  const empty = summarizeKey(null);
  assert.equal(empty.length, 0);
});

test('total 统计所有事件（含未知类别）', () => {
  const st = createStorageAccessState();
  decideStorageAccess(st, { kind: KIND_SESSION, frameUrl: 'https://a.test', topUrl: 'https://a.test' }, 0);
  decideStorageAccess(st, { kind: 'x' }, 1);
  assert.equal(st.total, 2);
});

test('默认阈值常量为正数', () => {
  assert.ok(DEFAULT_MAX_ACCESS_PER_WINDOW > 0);
});

test('桶数量受 MAX_STORAGE_BUCKETS 上界约束并淘汰最旧桶', () => {
  const st = createStorageAccessState();
  // 造出超过上界数量的不同“框架源”桶
  for (let i = 0; i < MAX_STORAGE_BUCKETS + 5; i++) {
    decideStorageAccess(st, {
      kind: KIND_SESSION,
      frameUrl: `https://f${i}.test/`,
      topUrl: 'https://top.test/',
    }, -1);
  }
  assert.ok(st.buckets.size <= MAX_STORAGE_BUCKETS, `size=${st.buckets.size}`);
  // 最早建立的 f0 桶应已被淘汰，桶集合里不再含其键
  const oldestKey = bucketKey(KIND_SESSION, 'https://f0.test', 'https://top.test', '');
  assert.equal(st.buckets.has(oldestKey), false);
});
