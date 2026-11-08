'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./crashloopguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows empty history', () => {
  const result = guard.evaluateCrashLoop([]);
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks crash budget', () => {
  const result = guard.evaluateCrashLoop([{ at: 1000 }, { at: 2000 }, { at: 3000 }, { at: 4000 }]);
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.BUDGET_EXCEEDED);
});

test('blocks crashes too fast', () => {
  const result = guard.evaluateCrashLoop([{ at: 1000 }, { at: 2000 }]);
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.TOO_FAST);
});

test('blocks invalid event', () => {
  const result = guard.evaluateCrashLoop([{ at: -1 }]);
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.INVALID_EVENT);
});

