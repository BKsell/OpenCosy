'use strict';

const test = require('node:test');
const assert = require('node:assert');
const C = require('./cleaner');

function sampleEntries() {
  return [
    { origin: 'https://example.com', storageType: 'cookies', bytes: 1024, lastAccessed: 1000 },
    { origin: 'https://sub.example.com', storageType: 'cookies', bytes: 512, lastAccessed: 2000 },
    { origin: 'http://notexample.com', storageType: 'localstorage', bytes: 2048, lastAccessed: 3000 },
    { origin: 'https://example.com', storageType: 'indexeddb', bytes: 8192, lastAccessed: 4000 },
    { origin: 'https://other.org', storageType: 'cookies', bytes: 128, lastAccessed: 5000 },
  ];
}

test('hostMatchesOrigin exact 只命中完全相等主机', () => {
  assert.strictEqual(C.hostMatchesOrigin('https://example.com', 'example.com', 'exact'), true);
  assert.strictEqual(C.hostMatchesOrigin('https://sub.example.com', 'example.com', 'exact'), false);
  assert.strictEqual(C.hostMatchesOrigin('http://notexample.com', 'example.com', 'exact'), false);
  assert.strictEqual(C.hostMatchesOrigin('https://EXAMPLE.com:8443/x', 'example.com', 'exact'), true);
});

test('hostMatchesOrigin subdomains 命中子域但不越标签', () => {
  assert.strictEqual(C.hostMatchesOrigin('https://sub.example.com', 'example.com', 'subdomains'), true);
  assert.strictEqual(C.hostMatchesOrigin('https://example.com', 'example.com', 'subdomains'), true);
  assert.strictEqual(C.hostMatchesOrigin('http://notexample.com', 'example.com', 'subdomains'), false);
  assert.strictEqual(C.hostMatchesOrigin('https://evil-example.com', 'example.com', 'subdomains'), false);
  assert.strictEqual(C.hostMatchesOrigin('https://a.b.example.com', 'example.com', 'subdomains'), true);
});

test('hostMatchesOrigin all 忽略主机条件', () => {
  assert.strictEqual(C.hostMatchesOrigin('https://whatever.com', 'x', 'all'), true);
  assert.strictEqual(C.hostMatchesOrigin('chrome-extension://abc', 'x', 'all'), true);
});

test('filterSiteEntries exact 模式按主机过滤并汇总', () => {
  const r = C.filterSiteEntries(sampleEntries(), { matchMode: 'exact', host: 'example.com' });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.targets.length, 2); // cookies + indexeddb
  assert.strictEqual(r.sites, 1);
  assert.strictEqual(r.totalBytes, 1024 + 8192);
  assert.deepStrictEqual(r.byType, { cookies: 1, indexeddb: 1 });
});

test('filterSiteEntries subdomains 模式把子域并入同一站点', () => {
  const r = C.filterSiteEntries(sampleEntries(), { matchMode: 'subdomains', host: 'example.com' });
  assert.strictEqual(r.targets.length, 3); // + sub.example.com
  assert.strictEqual(r.sites, 2);
});

test('filterSiteEntries all 模式命中全部去重后条目', () => {
  const entries = sampleEntries().concat([{ origin: 'https://example.com', storageType: 'cookies', bytes: 1, lastAccessed: 900 }]);
  const r = C.filterSiteEntries(entries, { matchMode: 'all' });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.targets.length, 5); // example.com cookies 去重
  assert.strictEqual(r.sites, 4);
});

test('filterSiteEntries storageTypes 过滤只留指定类型', () => {
  const r = C.filterSiteEntries(sampleEntries(), {
    matchMode: 'subdomains', host: 'example.com', storageTypes: ['cookies'],
  });
  assert.strictEqual(r.targets.length, 2);
  assert.ok(r.targets.every((t) => t.storageType === 'cookies'));
});

test('filterSiteEntries since 时间窗过滤 lastAccessed 更早的条目', () => {
  const r = C.filterSiteEntries(sampleEntries(), { matchMode: 'all', since: 1500 });
  // lastAccessed 1000 的 example.com cookies 被滤掉；0（未知）保留。
  assert.strictEqual(r.targets.length, 4);
  assert.ok(!r.targets.some((t) => t.origin === 'https://example.com' && t.storageType === 'cookies'));
});

test('filterSiteEntries 非法入参被拒绝', () => {
  assert.strictEqual(C.filterSiteEntries(null, {}).reason, 'bad-entries');
  assert.strictEqual(C.filterSiteEntries([], { matchMode: 'exact', host: '' }).reason, 'bad-host');
  assert.strictEqual(C.filterSiteEntries([], { matchMode: 'weird', host: 'x' }).reason, 'ok' === 'ok' ? undefined : undefined);
  const r = C.filterSiteEntries([], { matchMode: 'weird', host: 'x' });
  assert.strictEqual(r.ok, true); // 非法模式回退 exact
  const many = [];
  for (let i = 0; i < C.MAX_TARGETS + 1; i++) many.push({ origin: 'https://h' + i + '.com', storageType: 'cookies' });
  assert.strictEqual(C.filterSiteEntries(many, { matchMode: 'all' }).reason, 'too-many-targets');
});

test('normalizeSince / normalizeMatchMode 边界', () => {
  assert.strictEqual(C.normalizeSince(-5), 0);
  assert.strictEqual(C.normalizeSince(NaN), 0);
  assert.strictEqual(C.normalizeSince(Infinity), 0);
  assert.strictEqual(C.normalizeSince('100'), 0);
  assert.strictEqual(C.normalizeSince(12.9), 12);
  assert.strictEqual(C.normalizeMatchMode('SUB'), 'exact');
  assert.strictEqual(C.normalizeMatchMode('all'), 'all');
  assert.strictEqual(C.normalizeMatchMode(undefined), 'exact');
});

test('summarizePlan 生成计划快照', () => {
  const f = C.filterSiteEntries(sampleEntries(), { matchMode: 'exact', host: 'example.com' });
  const s = C.summarizePlan(f, ['cookies', 'indexeddb']);
  assert.strictEqual(s.ok, true);
  assert.strictEqual(s.sites, 1);
  assert.strictEqual(s.targetCount, 2);
  assert.strictEqual(s.totalBytes, 1024 + 8192);
  assert.deepStrictEqual(s.actions, ['cookies', 'indexeddb']);
  assert.ok(s.createdAt > 0);
});

test('recordCleanAudit 追加条目并封顶', () => {
  const log = [];
  for (let i = 0; i < C.MAX_AUDIT_ENTRIES + 10; i++) {
    const r = C.recordCleanAudit(log, { mode: 'exact', host: 'h' + i + '.com', sites: 1, targetCount: 2, bytes: i, actions: ['cookies'] });
    assert.strictEqual(r.ok, true);
  }
  assert.strictEqual(log.length, C.MAX_AUDIT_ENTRIES);
  assert.strictEqual(log[0].host, 'h10.com'); // 最老的被挤出
  assert.strictEqual(log[log.length - 1].host, 'h' + (C.MAX_AUDIT_ENTRIES + 9) + '.com');
});

test('recordCleanAudit 拒绝坏入参', () => {
  assert.strictEqual(C.recordCleanAudit(null, {}).reason, 'bad-log');
  assert.strictEqual(C.recordCleanAudit([], null).reason, 'bad-event');
  const log = [];
  const r = C.recordCleanAudit(log, { mode: 'exact', host: 'a.com', sites: 1 });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.entry.actions.length, 0);
  assert.strictEqual(r.entry.bytes, 0);
});

test('pruneAuditLog 清空 / 保留最近', () => {
  const log = [];
  for (let i = 0; i < 5; i++) C.recordCleanAudit(log, { host: 'h' + i + '.com' });
  const cleared = C.pruneAuditLog(log, 0);
  assert.deepStrictEqual(cleared.log, []);
  const kept = C.pruneAuditLog(log, 3);
  assert.strictEqual(kept.log.length, 3);
  assert.strictEqual(kept.log[0].host, 'h2.com');
  assert.strictEqual(C.pruneAuditLog('x', 1).reason, 'bad-log');
});

test('classifyStorageType 归一化已知类型', () => {
  assert.strictEqual(C.classifyStorageType('cookies'), 'cookies');
  assert.strictEqual(C.classifyStorageType('LOCALSTORAGE'), 'localstorage');
  assert.strictEqual(C.classifyStorageType('serviceWorkers'), 'serviceworkers');
  assert.strictEqual(C.classifyStorageType('unknown-thing'), 'unknown-thing');
  assert.strictEqual(C.classifyStorageType(null), '');
});
