'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./sslstripguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows https to https', () => {
  const result = guard.evaluateTransition('https://example.com/a', 'https://example.com/b');
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks https downgrade', () => {
  const result = guard.evaluateTransition('https://example.com/a', 'http://example.com/b');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.DOWNGRADE);
});

test('blocks hsts host over http', () => {
  const result = guard.evaluateTransition('http://other.com/', 'http://bank.example.com/a');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.HSTS_BYPASS);
});

test('blocks credentials in target', () => {
  const result = guard.evaluateTransition('https://example.com/', 'https://user:pass@example.com/b');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.CREDENTIALS);
});

test('blocks invalid target', () => {
  const result = guard.evaluateTransition('https://example.com/', 'not a url');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.INVALID);
});

