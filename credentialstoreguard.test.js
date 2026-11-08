'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./credentialstoreguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows keychain backend', () => {
  const result = guard.evaluateCredentialStore({ backend: 'keychain' });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks plaintext backend', () => {
  const result = guard.evaluateCredentialStore({ backend: 'plaintext' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.PLAINTEXT_STORE);
});

test('blocks unknown backend', () => {
  const result = guard.evaluateCredentialStore({ backend: 'mystery' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.UNKNOWN_BACKEND);
});

test('blocks weak encryption', () => {
  const result = guard.evaluateCredentialStore({ backend: 'keychain', algorithm: 'aes-128-cbc' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.WEAK_ENCRYPTION);
});

test('blocks world readable store', () => {
  const result = guard.evaluateCredentialStore({ backend: 'keychain', worldReadable: true });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.FILE_WORLD_READABLE);
});

