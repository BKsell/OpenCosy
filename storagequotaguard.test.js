'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./storagequotaguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows default quota', () => {
  const result = guard.evaluateStorageQuota({ origin: 'https://example.com' });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks zero quota', () => {
  const result = guard.evaluateStorageQuota({ origin: 'https://example.com', quota: 0 });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.QUOTA_INVALID);
});

test('blocks oversized quota', () => {
  const result = guard.evaluateStorageQuota({ origin: 'https://example.com', quota: 1073741824 });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.QUOTA_TOO_LARGE);
});

test('blocks usage above quota', () => {
  const result = guard.evaluateStorageQuota({ origin: 'https://example.com', quota: 1024, usage: 2048 });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.USAGE_EXCEEDS_QUOTA);
});

test('blocks opaque origin', () => {
  const result = guard.evaluateStorageQuota({ origin: 'about:blank' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.OPAQUE_ORIGIN);
});

test('blocks invalid origin', () => {
  const result = guard.evaluateStorageQuota({ origin: 'nope' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.ORIGIN_INVALID);
});

