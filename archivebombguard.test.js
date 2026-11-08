'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./archivebombguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows small archive', () => {
  const result = guard.evaluateArchive({ entries: [{ name: 'a/b.txt', size: 10, compressed: 5 }], depth: 0 });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks too many entries', () => {
  const result = guard.evaluateArchive({ entries: new Array(20001).fill({ name: 'x', size: 1, compressed: 1 }) });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.TOO_MANY_ENTRIES);
});

test('blocks entry traversal', () => {
  const result = guard.evaluateArchive({ entries: [{ name: '../x', size: 1, compressed: 1 }] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.ENTRY_TRAVERSAL);
});

test('blocks absolute entry', () => {
  const result = guard.evaluateArchive({ entries: [{ name: '/etc/passwd', size: 1, compressed: 1 }] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.ABSOLUTE_ENTRY);
});

test('blocks compression ratio bomb', () => {
  const result = guard.evaluateArchive({ entries: [{ name: 'a', size: 100000, compressed: 1 }] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.RATIO_EXCEEDED);
});

test('blocks nested archive depth', () => {
  const result = guard.evaluateArchive({ entries: [], depth: 5 });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.NESTED_ARCHIVE);
});

