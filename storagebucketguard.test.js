'use strict';

// storagebucketguard.test.js —— Storage Buckets：三方、桶名校验、桶数/配额、persist、超长 expires。

const test = require('node:test');
const assert = require('node:assert/strict');
const s = require('./storagebucketguard');
const { StorageBucketGuard, SB_REASON, defaultStorageBucketPolicy } = s;

let now = 1_700_000_000_000;
const clock = () => now;
function ctx(over) { return Object.assign({ origin: 'https://app.example.com', isTopFrame: true }, over || {}); }

test('合规建桶放行', () => {
  const g = new StorageBucketGuard(undefined, clock);
  assert.equal(g.decideOpen(ctx(), 'cache-a', { quota: 1024 }).decision, 'allow');
});

test('三方上下文默认拒绝', () => {
  const g = new StorageBucketGuard(undefined, clock);
  assert.equal(g.decideOpen(ctx({ isTopFrame: false }), 'a', {}).reason, SB_REASON.THIRD_PARTY);
});

test('非 https 拒绝', () => {
  const g = new StorageBucketGuard(undefined, clock);
  assert.equal(g.decideOpen(ctx({ origin: 'http://x' }), 'a', {}).reason, SB_REASON.INSECURE_ORIGIN);
});

test('桶名非法/超长/控制字符拒绝', () => {
  const g = new StorageBucketGuard(undefined, clock);
  assert.equal(g.decideOpen(ctx(), '', {}).reason, SB_REASON.BAD_NAME);
  assert.equal(g.decideOpen(ctx(), 'x'.repeat(80), {}).reason, SB_REASON.NAME_TOO_LONG);
  assert.equal(g.decideOpen(ctx(), 'a\nb', {}).reason, SB_REASON.NAME_CONTROL_CHAR);
});

test('桶数量上限', () => {
  const pol = defaultStorageBucketPolicy();
  pol.maxBucketsPerOrigin = 2;
  const g = new StorageBucketGuard(pol, clock);
  assert.equal(g.decideOpen(ctx(), 'a', {}).decision, 'allow');
  assert.equal(g.decideOpen(ctx(), 'b', {}).decision, 'allow');
  assert.equal(g.decideOpen(ctx(), 'c', {}).reason, SB_REASON.TOO_MANY_BUCKETS);
});

test('单桶配额超上限拒绝', () => {
  const g = new StorageBucketGuard(undefined, clock);
  assert.equal(g.decideOpen(ctx(), 'big', { quota: 999 * 1024 * 1024 }).reason, SB_REASON.QUOTA_TOO_LARGE);
});

test('源总配额超限拒绝', () => {
  const pol = defaultStorageBucketPolicy();
  pol.totalQuotaPerOrigin = 1000;
  const g = new StorageBucketGuard(pol, clock);
  assert.equal(g.decideOpen(ctx(), 'a', { quota: 600 }).decision, 'allow');
  assert.equal(g.decideOpen(ctx(), 'b', { quota: 600 }).reason, SB_REASON.QUOTA_EXCEEDED);
});

test('persist 默认拒绝', () => {
  const g = new StorageBucketGuard(undefined, clock);
  assert.equal(g.decideOpen(ctx(), 'a', { persisted: true }).reason, SB_REASON.PERSIST_DISABLED);
});

test('expires 过远拒绝', () => {
  const g = new StorageBucketGuard(undefined, clock);
  assert.equal(g.decideOpen(ctx(), 'a', { expires: now + 100 * 24 * 3600 * 1000 }).reason, SB_REASON.EXPIRES_TOO_FAR);
});
