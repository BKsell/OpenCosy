'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./redirectchainguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows single https hop', () => {
  const result = guard.evaluateRedirectChain(['https://a.example.com/', 'https://a.example.com/b']);
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks https downgrade', () => {
  const result = guard.evaluateRedirectChain(['https://a.example.com/', 'http://a.example.com/b']);
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.DOWNGRADE);
});

test('blocks redirect loop', () => {
  const result = guard.evaluateRedirectChain(['https://a.example.com/', 'https://a.example.com/']);
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.LOOP);
});

test('blocks cross scheme redirect', () => {
  const result = guard.evaluateRedirectChain(['https://a.example.com/', 'ftp://a.example.com/b']);
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.CROSS_SCHEME);
});

test('blocks invalid location', () => {
  const result = guard.evaluateRedirectChain(['https://a.example.com/', 'not a url']);
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.INVALID);
});

test('blocks too many hops', () => {
  const result = guard.evaluateRedirectChain(Array.from({ length: 13 }, function (v, i) { return 'https://a.example.com/' + i; }));
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.TOO_MANY_HOPS);
});

