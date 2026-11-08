'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./devicemotionguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows https motion request', () => {
  const result = guard.evaluateMotionRequest({ origin: 'https://example.com', rateHz: 60 });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks insecure origin', () => {
  const result = guard.evaluateMotionRequest({ origin: 'http://example.com', rateHz: 60 });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.INSECURE_ORIGIN);
});

test('blocks denied permission', () => {
  const result = guard.evaluateMotionRequest({ origin: 'https://example.com', permission: 'denied' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.PERMISSION_DENIED);
});

test('blocks excessive sample rate', () => {
  const result = guard.evaluateMotionRequest({ origin: 'https://example.com', rateHz: 500 });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.RATE_TOO_HIGH);
});

test('blocks long capture window', () => {
  const result = guard.evaluateMotionRequest({ origin: 'https://example.com', captureMs: 3600000 });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.CAPTURE_TOO_LONG);
});

