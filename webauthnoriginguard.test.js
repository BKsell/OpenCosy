'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./webauthnoriginguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows registrable rp id', () => {
  const result = guard.evaluateWebauthn({ origin: 'https://login.example.com', rpId: 'example.com' });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks rp id mismatch', () => {
  const result = guard.evaluateWebauthn({ origin: 'https://login.example.com', rpId: 'evil.com' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.RP_ID_MISMATCH);
});

test('blocks insecure origin', () => {
  const result = guard.evaluateWebauthn({ origin: 'http://login.example.com', rpId: 'example.com' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.INSECURE_ORIGIN);
});

test('blocks public suffix rp id', () => {
  const result = guard.evaluateWebauthn({ origin: 'https://com', rpId: 'com' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.RP_ID_PUBLIC_SUFFIX);
});

test('blocks weak challenge', () => {
  const result = guard.evaluateWebauthn({ origin: 'https://login.example.com', rpId: 'example.com', challenge: 'aaaaaaaaaaaaaaaa' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.CHALLENGE_WEAK);
});

test('blocks oversized timeout', () => {
  const result = guard.evaluateWebauthn({ origin: 'https://login.example.com', rpId: 'example.com', timeout: 999999 });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.TIMEOUT_TOO_LONG);
});

