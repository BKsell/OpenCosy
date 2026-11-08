'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./cachepartitionguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows browser partition', () => {
  const result = guard.evaluateCachePartition('browser');
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks empty partition', () => {
  const result = guard.evaluateCachePartition('');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.EMPTY);
});

test('blocks traversal partition', () => {
  const result = guard.evaluateCachePartition('../x');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.PATH_TRAVERSAL);
});

test('blocks shared partition', () => {
  const result = guard.evaluateCachePartition('shared-app');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.SHARED_PARTITION);
});

test('blocks invalid characters', () => {
  const result = guard.evaluateCachePartition('a$b');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.INVALID_CHARS);
});

test('blocks oversized partition', () => {
  const result = guard.evaluateCachePartition(new Array(70).join('a'));
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.TOO_LONG);
});

