'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./preloadpathguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows preload inside app root', () => {
  const result = guard.evaluatePreload('/opt/app/preload.js', { appRoot: '/opt/app' });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('treats empty preload as none', () => {
  const result = guard.evaluatePreload('');
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.EMPTY);
});

test('blocks relative preload', () => {
  const result = guard.evaluatePreload('preload.js');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.RELATIVE);
});

test('blocks traversal', () => {
  const result = guard.evaluatePreload('/opt/app/../etc/p.js');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.TRAVERSAL);
});

test('blocks non script extension', () => {
  const result = guard.evaluatePreload('/opt/app/preload.txt');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.WRONG_EXTENSION);
});

test('blocks temp directory preload', () => {
  const result = guard.evaluatePreload('/tmp/preload.js');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.TEMP_DIR);
});

test('blocks preload outside app root', () => {
  const result = guard.evaluatePreload('/opt/other/preload.js', { appRoot: '/opt/app' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.OUTSIDE_APP);
});

