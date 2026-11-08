'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./fileaccessguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows file inside allowed root', () => {
  const result = guard.evaluateFileUrl(('file://' + root) + '/doc.txt', { roots: [root] });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks system path', () => {
  const result = guard.evaluateFileUrl('file:///etc/passwd', { roots: [root] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.SYSTEM_PATH);
});

test('blocks remote authority', () => {
  const result = guard.evaluateFileUrl('file://evil.com/x', { roots: [root] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.REMOTE_AUTHORITY);
});

test('blocks path outside root', () => {
  const result = guard.evaluateFileUrl('file:///opt/other/x.txt', { roots: [root] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.OUTSIDE_HOME);
});

test('blocks non file scheme', () => {
  const result = guard.evaluateFileUrl('https://example.com/x', { roots: [root] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.NOT_FILE_SCHEME);
});

test('blocks sensitive file name', () => {
  const result = guard.evaluateFileUrl(('file://' + root) + '/.ssh/id_rsa', { roots: [root] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.SENSITIVE_FILE);
});

