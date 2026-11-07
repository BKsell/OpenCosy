'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./certpinningguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows primary and backup pin', () => {
  const result = guard.evaluatePinningPolicy({ host: 'api.example.com', pins: ['sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'] });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks missing host', () => {
  const result = guard.evaluatePinningPolicy({ pins: ['sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.HOST_MISSING);
});

test('blocks empty pin set', () => {
  const result = guard.evaluatePinningPolicy({ host: 'api.example.com', pins: [] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.NO_PINS);
});

test('blocks weak sha1 pin', () => {
  const result = guard.evaluatePinningPolicy({ host: 'api.example.com', pins: ['sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.WEAK_HASH);
});

test('blocks missing backup pin', () => {
  const result = guard.evaluatePinningPolicy({ host: 'api.example.com', pins: ['sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.NO_BACKUP);
});

test('blocks expired pin set', () => {
  const result = guard.evaluatePinningPolicy({ host: 'api.example.com', pins: ['sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'], expiresAt: 1 });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.EXPIRY_INVALID);
});

