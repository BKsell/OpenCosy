'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./dragdropfileguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows trusted document drop', () => {
  const result = guard.evaluateDrop({ files: [{ path: 'doc.txt' }], trusted: true });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks empty drop', () => {
  const result = guard.evaluateDrop({ files: [], trusted: true });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.EMPTY);
});

test('blocks too many files', () => {
  const result = guard.evaluateDrop({ files: new Array(300).fill({ path: 'doc.txt' }), trusted: true });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.TOO_MANY_FILES);
});

test('blocks untrusted drop', () => {
  const result = guard.evaluateDrop({ files: [{ path: 'doc.txt' }] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.UNTRUSTED_SOURCE);
});

test('blocks dll payload', () => {
  const result = guard.evaluateDrop({ files: [{ path: 'payload.dll' }], trusted: true });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.DLL_PAYLOAD);
});

test('blocks symlink entry', () => {
  const result = guard.evaluateDrop({ files: [{ path: 'doc.txt', isSymlink: true }], trusted: true });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.SYMLINK_ENTRY);
});

