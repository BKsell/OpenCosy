'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./javascripturlguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows https url', () => {
  const result = guard.evaluateUrlScheme('https://example.com/x');
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks javascript scheme', () => {
  const result = guard.evaluateUrlScheme('  javascript:alert(1)');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.SCRIPT_SCHEME);
});

test('blocks inline data url', () => {
  const result = guard.evaluateUrlScheme('data:text/html,<b>x</b>');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.INLINE_DATA);
});

test('blocks vbscript scheme', () => {
  const result = guard.evaluateUrlScheme('vbscript:msgbox');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.VBSCRIPT);
});

test('blocks empty url', () => {
  const result = guard.evaluateUrlScheme('');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.EMPTY);
});

test('blocks encoded javascript', () => {
  const result = guard.evaluateUrlScheme('https://example.com/%6a%61%76%61%73%63%72%69%70%74:alert(1)');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.ENCODED_SCRIPT);
});

