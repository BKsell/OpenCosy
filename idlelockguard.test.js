'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./idlelockguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows five minute idle lock', () => {
  const result = guard.evaluateIdleLock({ enabled: true, idleMs: 300000, lockOnIdle: true });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks disabled idle lock', () => {
  const result = guard.evaluateIdleLock({ enabled: false });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.IDLE_DISABLED);
});

test('blocks too short idle timeout', () => {
  const result = guard.evaluateIdleLock({ enabled: true, idleMs: 1000 });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.TIMEOUT_INVALID);
});

test('blocks too long idle timeout', () => {
  const result = guard.evaluateIdleLock({ enabled: true, idleMs: 3600000 });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.TIMEOUT_TOO_LONG);
});

test('blocks unlocked idle state', () => {
  const result = guard.evaluateIdleLock({ enabled: true, idleMs: 300000, lockOnIdle: false });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.LOCK_UNCONFIRMED);
});

