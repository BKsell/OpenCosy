'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./downloadextguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows pdf download', () => {
  const result = guard.evaluateDownloadName('report.pdf');
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks empty name', () => {
  const result = guard.evaluateDownloadName('');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.EMPTY);
});

test('blocks executable download', () => {
  const result = guard.evaluateDownloadName('evil.exe');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.EXECUTABLE);
});

test('blocks path separator', () => {
  const result = guard.evaluateDownloadName('../x.txt');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.PATH_SEPARATOR);
});

test('blocks hidden executable', () => {
  const result = guard.evaluateDownloadName('.hidden.exe');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.HIDDEN_EXECUTABLE);
});

