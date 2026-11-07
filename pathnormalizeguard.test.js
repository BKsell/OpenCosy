'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./pathnormalizeguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows plain relative path', () => {
  const result = guard.evaluateRelativePath('a/b/c.txt');
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks traversal segment', () => {
  const result = guard.evaluateRelativePath('../x');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.TRAVERSAL);
});

test('blocks absolute path', () => {
  const result = guard.evaluateRelativePath('/etc/passwd');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.ABSOLUTE);
});

test('blocks drive letter path', () => {
  const result = guard.evaluateRelativePath('C:/x');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.DRIVE_PATH);
});

test('blocks unc path', () => {
  const result = guard.evaluateRelativePath('//srv/share/x');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.UNC_PATH);
});

test('blocks alternate data stream', () => {
  const result = guard.evaluateRelativePath('dir/a:b.txt');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.ADS);
});

