'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./tlsversionguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows tls 1.2', () => {
  const result = guard.evaluateTlsConfig({ minVersion: 'TLSv1.2' });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks tls 1.0', () => {
  const result = guard.evaluateTlsConfig({ minVersion: 'TLSv1' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.TLS_TOO_OLD);
});

test('blocks unknown version', () => {
  const result = guard.evaluateTlsConfig({ minVersion: 'SSLv3' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.TLS_UNKNOWN);
});

test('blocks weak cipher', () => {
  const result = guard.evaluateTlsConfig({ minVersion: 'TLSv1.2', ciphers: 'AES128-SHA:RC4-SHA' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.WEAK_CIPHER);
});

test('blocks disabled verification', () => {
  const result = guard.evaluateTlsConfig({ minVersion: 'TLSv1.2', rejectUnauthorized: false });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.NO_VERIFY);
});

