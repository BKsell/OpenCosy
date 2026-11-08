'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./mediakeysguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows focused play key', () => {
  const result = guard.evaluateMediaKeyRequest({ enabled: true, action: 'play', trustedFocus: true });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks disabled media keys', () => {
  const result = guard.evaluateMediaKeyRequest({ enabled: false, action: 'play', trustedFocus: true });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.NOT_ENABLED);
});

test('blocks untrusted focus', () => {
  const result = guard.evaluateMediaKeyRequest({ enabled: true, action: 'play', trustedFocus: false });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.UNTRUSTED_FOCUS);
});

test('blocks unknown action', () => {
  const result = guard.evaluateMediaKeyRequest({ enabled: true, action: 'explode', trustedFocus: true });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.NO_REGISTERED_HANDLER);
});

