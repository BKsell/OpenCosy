'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./clipboardhtmlguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows plain text', () => {
  const result = guard.evaluateClipboard({ text: 'hello' });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks empty payload', () => {
  const result = guard.evaluateClipboard({});
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.EMPTY);
});

test('flags html for stripping', () => {
  const result = guard.evaluateClipboard({ html: '<b>x</b>' });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.HTML_PRESENT);
});

test('blocks script html', () => {
  const result = guard.evaluateClipboard({ html: '<script>alert(1)</script>' }, { allowHtml: true });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.SCRIPT_CONTENT);
});

test('blocks event handler html', () => {
  const result = guard.evaluateClipboard({ html: '<img onerror=boom()>' }, { allowHtml: true });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.EVENT_HANDLER);
});

