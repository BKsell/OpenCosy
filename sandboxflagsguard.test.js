'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./sandboxflagsguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows hardened preferences', () => {
  const result = guard.evaluatePreferences({ sandbox: true, contextIsolation: true, nodeIntegration: false });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks disabled sandbox', () => {
  const result = guard.evaluatePreferences({ sandbox: false });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.SANDBOX_OFF);
});

test('blocks missing context isolation', () => {
  const result = guard.evaluatePreferences({ sandbox: true });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.CONTEXT_ISOLATION_OFF);
});

test('blocks node integration', () => {
  const result = guard.evaluatePreferences({ sandbox: true, contextIsolation: true, nodeIntegration: true });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.NODE_INTEGRATION_ON);
});

test('blocks disabled web security', () => {
  const result = guard.evaluatePreferences({ sandbox: true, contextIsolation: true, webSecurity: false });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.WEB_SECURITY_OFF);
});

