'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./wantdigestguard');

test('缺头不改动', () => {
  const r = guard.applyWantDigestGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('sha-256 合规', () => {
  const headers = { 'want-digest': 'sha-256' };
  const r = guard.applyWantDigestGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('带参数合规', () => {
  const headers = { 'want-digest': 'sha-256;q=0.5' };
  const r = guard.applyWantDigestGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('md5 被拒绝', () => {
  const headers = { 'want-digest': 'md5, sha-256' };
  const r = guard.applyWantDigestGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.WEAK_ALGORITHM);
  assert.strictEqual(headers['want-digest'], 'sha-256');
});

test('未知算法被剔除', () => {
  const headers = { 'want-digest': 'blake3' };
  const r = guard.applyWantDigestGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['want-digest'], undefined);
});

test('算法过多截断', () => {
  const headers = { 'want-digest': 'sha-256, sha-512, sha-256-sess, sha-512-sess' };
  const r = guard.applyWantDigestGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
  assert.strictEqual(headers['want-digest'].split(',').length, 3);
});

test('空值删除', () => {
  const headers = { 'want-digest': ' ' };
  const r = guard.applyWantDigestGuard(headers);
  assert.strictEqual(headers['want-digest'], undefined);
});
