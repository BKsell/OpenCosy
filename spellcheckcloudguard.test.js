'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./spellcheckcloudguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows local provider', () => {
  const result = guard.evaluateSpellcheck({ provider: 'hunspell' });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks cloud provider', () => {
  const result = guard.evaluateSpellcheck({ provider: 'google' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.CLOUD_PROVIDER);
});

test('blocks unknown provider', () => {
  const result = guard.evaluateSpellcheck({ provider: 'mystery' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.UNKNOWN_PROVIDER);
});

test('blocks remote dictionary', () => {
  const result = guard.evaluateSpellcheck({ provider: 'local', dictionaryUrl: 'https://dict.example.com/en.bin' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.REMOTE_DICTIONARY);
});

test('blocks insecure endpoint', () => {
  const result = guard.evaluateSpellcheck({ provider: 'local', endpoint: 'http://dict.example.com/api' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.INSECURE_ENDPOINT);
});

