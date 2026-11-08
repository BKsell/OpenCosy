'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./urlcredentialstripguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows clean url', () => {
  const result = guard.evaluateUrl('https://example.com/a');
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks userinfo url', () => {
  const result = guard.evaluateUrl('https://user:pass@example.com/a');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.CREDENTIALS);
});

test('blocks empty url', () => {
  const result = guard.evaluateUrl('');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.EMPTY);
});

test('blocks invalid url', () => {
  const result = guard.evaluateUrl('not a url');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.INVALID);
});

test('blocks token in logged url', () => {
  const result = guard.evaluateUrl('https://example.com/cb?token=abc', { forLog: true });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.LOG_LEAK);
});

