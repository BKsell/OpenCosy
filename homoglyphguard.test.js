'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./homoglyphguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows ascii host', () => {
  const result = guard.evaluateHomoglyph('https://example.com/x');
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks punycode host', () => {
  const result = guard.evaluateHomoglyph('https://xn--80ak6aa92e.com/x');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.PUNYCODE);
});

test('blocks non url input', () => {
  const result = guard.evaluateHomoglyph('not a url');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.BAD_URL);
});

test('blocks ip literal when required', () => {
  const result = guard.evaluateHomoglyph('https://10.0.0.1/x', { blockIpLiteral: true });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.IP_LITERAL);
});

test('blocks host mismatch', () => {
  const result = guard.evaluateHomoglyph('https://evil.com/x', { expectedHost: 'example.com' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.MIXED_SCRIPT);
});

