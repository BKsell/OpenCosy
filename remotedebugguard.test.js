'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./remotedebugguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows disabled debugging', () => {
  const result = guard.evaluateRemoteDebug({ enabled: false });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.DISABLED);
});

test('allows loopback debugging', () => {
  const result = guard.evaluateRemoteDebug({ enabled: true, address: '127.0.0.1' });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks wildcard bind', () => {
  const result = guard.evaluateRemoteDebug({ enabled: true, address: '0.0.0.0' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.WILDCARD_BIND);
});

test('blocks missing address', () => {
  const result = guard.evaluateRemoteDebug({ enabled: true });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.MISSING_ADDRESS);
});

test('blocks public bind', () => {
  const result = guard.evaluateRemoteDebug({ enabled: true, address: '10.1.2.3' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.PUBLIC_BIND);
});

