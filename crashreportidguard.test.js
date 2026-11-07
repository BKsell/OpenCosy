'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./crashreportidguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows uuid v4 crash id', () => {
  const result = guard.evaluateCrashReport({ id: '3f4b8e2a-1c9d-4f6b-8a2e-5b7c9d1e3f4a' });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks missing crash id', () => {
  const result = guard.evaluateCrashReport({});
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.ID_MISSING);
});

test('blocks malformed crash id', () => {
  const result = guard.evaluateCrashReport({ id: 'crash-123' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.ID_FORMAT);
});

test('blocks oversized payload', () => {
  const result = guard.evaluateCrashReport({ id: '3f4b8e2a-1c9d-4f6b-8a2e-5b7c9d1e3f4a', payload: new Array(70000).join('a') });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.PAYLOAD_TOO_LARGE);
});

test('blocks pii in report', () => {
  const result = guard.evaluateCrashReport({ id: '3f4b8e2a-1c9d-4f6b-8a2e-5b7c9d1e3f4a', pii: { email: true } });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.PII_IN_REPORT);
});

test('blocks duplicate crash id', () => {
  const result = guard.evaluateCrashReport({ id: '3f4b8e2a-1c9d-4f6b-8a2e-5b7c9d1e3f4a' }, new Set(['3f4b8e2a-1c9d-4f6b-8a2e-5b7c9d1e3f4a']));
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.ID_DUPLICATE);
});

