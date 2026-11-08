'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./sessionpartitionguard');

test('默认使用临时分区', () => {
  const r = guard.applySessionPartitionGuard({ url: 'https://a.example.com' });
  assert.strictEqual(r.ephemeral, true);
  assert.strictEqual(r.partition.startsWith('session:'), true);
});

test('显式持久化分区', () => {
  const r = guard.applySessionPartitionGuard({ url: 'https://a.example.com', options: { persist: true } });
  assert.strictEqual(r.partition, 'persist:example.com');
  assert.strictEqual(r.ephemeral, false);
});

test('第三方存储默认被拒', () => {
  const r = guard.applySessionPartitionGuard({ url: 'https://tracker.example.org/x', topUrl: 'https://bank.example.com' });
  assert.strictEqual(r.thirdParty, true);
  assert.strictEqual(r.reason, guard.REASON.THIRD_PARTY_EPHEMERAL);
  assert.strictEqual(r.partition, '');
});

test('显式允许第三方存储时仍为临时分区', () => {
  const r = guard.applySessionPartitionGuard({ url: 'https://cdn.example.org/x', topUrl: 'https://bank.example.com', allowThirdPartyStorage: true, options: { persist: true } });
  assert.strictEqual(r.thirdParty, true);
  assert.strictEqual(r.ephemeral, true);
  assert.strictEqual(r.partition.startsWith('session:'), true);
});

test('http 源默认拒绝', () => {
  const r = guard.applySessionPartitionGuard({ url: 'http://a.example.com' });
  assert.strictEqual(r.reason, guard.REASON.INSECURE);
});

test('非法 URL 返回 INVALID', () => {
  const r = guard.applySessionPartitionGuard({ url: 'not-a-url' });
  assert.strictEqual(r.reason, guard.REASON.INVALID);
});

test('分区名校验接受合法值', () => {
  assert.strictEqual(guard.validatePartitionName('persist:abc.def-1').valid, true);
  assert.strictEqual(guard.validatePartitionName('random').valid, false);
});

test('批量审计统计临时分区数量', () => {
  const report = guard.auditPartitionBatch([
    { url: 'https://a.example.com' },
    { url: 'https://b.example.com', options: { persist: true } },
    { url: 'not-a-url' },
  ]);
  assert.strictEqual(report.total, 3);
  assert.strictEqual(report.ephemeral, 2);
  assert.strictEqual(report.findings.length, 1);
});
