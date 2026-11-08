'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./autoplaypolicyguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows muted autoplay', () => {
  const result = guard.evaluateAutoplay({ origin: 'https://example.com', muted: true });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks unrestricted autoplay', () => {
  const result = guard.evaluateAutoplay({ origin: 'https://example.com', allowAll: true });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.AUTOPLAY_ALLOWED);
});

test('blocks unmuted autoplay without gesture', () => {
  const result = guard.evaluateAutoplay({ origin: 'https://example.com', muted: false });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.GESTURE_REQUIRED);
});

test('blocks invalid origin', () => {
  const result = guard.evaluateAutoplay({ origin: 'nope' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.ORIGIN_INVALID);
});

