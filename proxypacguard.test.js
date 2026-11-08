'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./proxypacguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows https pac', () => {
  const result = guard.evaluateProxyPac('https://proxy.example.com/pac.js');
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('treats empty pac as disabled', () => {
  const result = guard.evaluateProxyPac('');
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.EMPTY);
});

test('blocks file pac', () => {
  const result = guard.evaluateProxyPac('file:///etc/passwd');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.LOCAL_FILE);
});

test('blocks plaintext pac', () => {
  const result = guard.evaluateProxyPac('http://proxy.example.com/pac.js');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.PLAINTEXT);
});

test('blocks pac credentials', () => {
  const result = guard.evaluateProxyPac('https://user:pass@proxy.example.com/pac.js');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.CREDENTIALS);
});

test('blocks loopback pac', () => {
  const result = guard.evaluateProxyPac('https://127.0.0.1/pac.js');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.LOOPBACK);
});

