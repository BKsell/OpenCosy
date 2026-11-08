'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./permissionpersistguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows session geolocation grant', () => {
  const result = guard.evaluatePermissionGrant({ origin: 'https://example.com', permission: 'geolocation', decision: 'granted' });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks persisted sensitive permission', () => {
  const result = guard.evaluatePermissionGrant({ origin: 'https://example.com', permission: 'geolocation', decision: 'granted', persist: true });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.PERSIST_SENSITIVE);
});

test('blocks unknown permission', () => {
  const result = guard.evaluatePermissionGrant({ origin: 'https://example.com', permission: 'mind-read' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.UNKNOWN_PERMISSION);
});

test('blocks persistence without expiry', () => {
  const result = guard.evaluatePermissionGrant({ origin: 'https://example.com', permission: 'notifications', persist: true });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.EXPIRY_MISSING);
});

test('blocks invalid origin', () => {
  const result = guard.evaluatePermissionGrant({ origin: 'nope', permission: 'notifications' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.ORIGIN_INVALID);
});

