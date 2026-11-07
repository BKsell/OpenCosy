'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./ipcallowlistguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows listed channel', () => {
  const result = guard.evaluateChannel('app:open', { allowlist: ['app:*'] });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks empty channel', () => {
  const result = guard.evaluateChannel('', { allowlist: ['app:*'] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.EMPTY);
});

test('blocks sensitive prefix', () => {
  const result = guard.evaluateChannel('internal:debug', { allowlist: ['internal:*'] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.SENSITIVE_PREFIX);
});

test('blocks wildcard channel name', () => {
  const result = guard.evaluateChannel('app*', { allowlist: ['app:*'] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.WILDCARD);
});

test('blocks unlisted channel', () => {
  const result = guard.evaluateChannel('evil:run', { allowlist: ['app:*'] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.NOT_ALLOWED);
});

