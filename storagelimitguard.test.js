'use strict';

// storagelimitguard.test.js —— 覆盖分区键规范化、键安全、单源/全局配额、
// LRU 淘汰候选、用量回退与快照恢复。

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  originPartitionKey,
  isValidStorageKey,
  StorageQuotaGuard,
  DEFAULT_LIMITS,
} = require('./storagelimitguard');

test('分区键规范化：大小写/尾点/默认端口归一', () => {
  assert.equal(originPartitionKey('https://Example.com'), 'https://example.com');
  assert.equal(originPartitionKey('https://example.com.'), 'https://example.com');
  assert.equal(originPartitionKey('https://example.com:443'), 'https://example.com');
  assert.equal(originPartitionKey('http://example.com:80'), 'http://example.com');
  assert.equal(originPartitionKey('https://example.com:8443'), 'https://example.com:8443');
  assert.equal(originPartitionKey('https://[2001:db8::1]'), 'https://2001:db8::1');
});

test('分区键拒绝非法输入', () => {
  for (const bad of [
    'example.com', 'ftp://x.com', 'https://x.com/path',
    'https://user@x.com', 'https://x.com:99999', '', null,
  ]) {
    assert.equal(originPartitionKey(bad), '', String(bad));
  }
});

test('存储键安全', () => {
  assert.equal(isValidStorageKey('__proto__', DEFAULT_LIMITS).ok, false);
  assert.equal(isValidStorageKey('constructor', DEFAULT_LIMITS).reason, 'key-prototype-pollution');
  assert.equal(isValidStorageKey('', DEFAULT_LIMITS).reason, 'key-empty');
  assert.equal(isValidStorageKey('a\x00b', DEFAULT_LIMITS).reason, 'key-control-char');
  assert.equal(isValidStorageKey('x'.repeat(DEFAULT_LIMITS.maxKeyLength + 1), DEFAULT_LIMITS).reason, 'key-too-long');
  assert.equal(isValidStorageKey('normal-key_1', DEFAULT_LIMITS).ok, true);
});

function makeGuard(limits, start = 1_000_000) {
  let t = start;
  return { g: new StorageQuotaGuard(limits, () => t), advance: ms => { t += ms; } };
}

const MB = 1024 * 1024;

test('正常写入允许并登记用量', () => {
  const { g } = makeGuard();
  const d = g.canStore({ origin: 'https://a.com', category: 'localStorage', key: 'k', addBytes: 100, isNewKey: true });
  assert.equal(d.allow, true);
  g.commitWrite('https://a.com', 'localStorage', 100, true);
  assert.equal(g.usage('https://a.com').originBytes, 100);
});

test('坏 origin 拒绝', () => {
  const { g } = makeGuard();
  assert.equal(g.canStore({ origin: 'not-a-url', addBytes: 1 }).reason, 'bad-origin');
});

test('危险键名拒绝', () => {
  const { g } = makeGuard();
  assert.equal(g.canStore({ origin: 'https://a.com', key: '__proto__', addBytes: 1 }).reason, 'key-prototype-pollution');
});

test('单源配额超限拒绝并给淘汰候选', () => {
  const { g } = makeGuard({ perOriginBytes: 10 * MB, reserveHeadroomBytes: 0, globalBytes: 1000 * MB });
  g.commitWrite('https://a.com', 'indexedDB', 8 * MB);
  const d = g.canStore({ origin: 'https://a.com', addBytes: 5 * MB });
  assert.equal(d.allow, false);
  assert.equal(d.reason, 'origin-quota-exceeded');
  assert.ok(d.evictCandidates.length >= 1);
});

test('全局保留余量触发拒绝', () => {
  const { g } = makeGuard({ perOriginBytes: 1000 * MB, globalBytes: 100 * MB, reserveHeadroomBytes: 20 * MB });
  g.commitWrite('https://a.com', 'cache', 85 * MB);
  const d = g.canStore({ origin: 'https://b.com', addBytes: 10 * MB });
  assert.equal(d.allow, false);
  assert.equal(d.reason, 'global-quota-exceeded');
  assert.ok(d.evictCandidates.length >= 1);
});

test('LRU 淘汰候选按最久未用排序', () => {
  const { g, advance } = makeGuard({ perOriginBytes: 1000 * MB, reserveHeadroomBytes: 0, globalBytes: 1000 * MB });
  g.commitWrite('https://old.com', 'cache', 10 * MB);
  advance(1000);
  g.commitWrite('https://new.com', 'cache', 10 * MB);
  const c = g.evictionCandidates(10 * MB);
  assert.equal(c[0].partitionKey, 'https://old.com');
});

test('clearOrigin 回收全局计数', () => {
  const { g } = makeGuard();
  g.commitWrite('https://a.com', 'cache', 500);
  assert.equal(g.clearOrigin('https://a.com'), true);
  assert.equal(g.usage('https://a.com').originBytes, 0);
  assert.equal(g.usage('https://a.com').globalBytes, 0);
});

test('release 不使计数为负', () => {
  const { g } = makeGuard();
  g.commitWrite('https://a.com', 'cache', 100);
  g.release('https://a.com', 'cache', 5000);
  assert.equal(g.usage('https://a.com').originBytes, 0);
});

test('键数量上限', () => {
  const { g } = makeGuard({ maxKeysPerOrigin: 2, perOriginBytes: 1000 * MB, reserveHeadroomBytes: 0, globalBytes: 1000 * MB });
  g.commitWrite('https://a.com', 'localStorage', 1, true);
  g.commitWrite('https://a.com', 'localStorage', 1, true);
  assert.equal(g.canStore({ origin: 'https://a.com', key: 'k3', addBytes: 1, isNewKey: true }).reason, 'too-many-keys');
});

test('源数量上限触发淘汰建议', () => {
  const { g } = makeGuard({ maxOrigins: 1, perOriginBytes: 1000 * MB, reserveHeadroomBytes: 0, globalBytes: 1000 * MB });
  g.commitWrite('https://a.com', 'cache', 10);
  const d = g.canStore({ origin: 'https://b.com', addBytes: 1 });
  assert.equal(d.reason, 'too-many-origins');
  assert.ok(d.evictCandidates.some(e => e.partitionKey === 'https://a.com'));
});

test('未知类别归入 other', () => {
  const { g } = makeGuard();
  const d = g.canStore({ origin: 'https://a.com', addBytes: 10, category: 'mystery' });
  assert.equal(d.allow, true);
  g.commitWrite('https://a.com', 'mystery', 10);
  assert.equal(g.usage('https://a.com').originBytes, 10);
});

test('快照恢复保持用量', () => {
  const a = makeGuard();
  a.g.commitWrite('https://a.com', 'indexedDB', 1234, true);
  const data = a.g.snapshot();
  const b = makeGuard();
  assert.equal(b.g.restore(data), true);
  assert.equal(b.g.usage('https://a.com').originBytes, 1234);
});

test('恢复非法数据不抛异常', () => {
  const { g } = makeGuard();
  assert.equal(g.restore(null), false);
  assert.equal(g.canStore({ origin: 'https://a.com', addBytes: 1 }).allow, true);
});
