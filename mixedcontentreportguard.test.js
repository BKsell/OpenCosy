'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./mixedcontentreportguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows display only mixed content', () => {
  const result = guard.evaluateMixedContent({ url: 'http://cdn.example.com/a.png', type: 'image' });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.DISPLAY_ONLY);
});

test('blocks blockable mixed content', () => {
  const result = guard.evaluateMixedContent({ url: 'http://cdn.example.com/a.js', type: 'script' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.BLOCKABLE);
});

test('blocks empty report', () => {
  const result = guard.evaluateMixedContent({});
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.EMPTY);
});

test('blocks credentials in report', () => {
  const result = guard.evaluateMixedContent({ url: 'http://user:pass@cdn.example.com/a.png', type: 'image' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.CREDENTIALS);
});

test('blocks host outside allowlist', () => {
  const result = guard.evaluateMixedContent({ url: 'http://evil.com/a.png', type: 'image' }, { allowHosts: ['cdn.example.com'] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.HOST_NOT_ALLOWED);
});

