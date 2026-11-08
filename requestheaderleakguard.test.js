'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./requestheaderleakguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows plain first party headers', () => {
  const result = guard.evaluateOutgoingHeaders([[ 'Accept', 'application/json' ]]);
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks cross origin credentials', () => {
  const result = guard.evaluateOutgoingHeaders([[ 'Authorization', 'Bearer abc' ]]);
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.CREDENTIAL_CROSS_ORIGIN);
});

test('allows same origin credentials', () => {
  const result = guard.evaluateOutgoingHeaders([[ 'Authorization', 'Bearer abc' ]], { sameOrigin: true });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks proxy authorization', () => {
  const result = guard.evaluateOutgoingHeaders([[ 'Proxy-Authorization', 'Basic abc' ]]);
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.PROXY_CREDENTIAL);
});

test('blocks spoofed forwarding header', () => {
  const result = guard.evaluateOutgoingHeaders([[ 'X-Forwarded-For', '1.2.3.4' ]]);
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.SPOOFED_FORWARD);
});

test('blocks control characters', () => {
  const result = guard.evaluateOutgoingHeaders([[ 'X-Test', 'a\u0001b' ]]);
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.CONTROL_CHARS);
});

