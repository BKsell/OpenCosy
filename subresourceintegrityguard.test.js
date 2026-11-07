'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./subresourceintegrityguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows script with sha384 integrity', () => {
  const result = guard.evaluateSubresource({ tag: 'script', src: 'https://cdn.example.com/a.js', integrity: 'sha384-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks inline data uri scripts', () => {
  const result = guard.evaluateSubresource({ tag: 'script', src: 'data:text/javascript,alert(1)' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.DATA_URI);
});

test('blocks plaintext transport', () => {
  const result = guard.evaluateSubresource({ tag: 'script', src: 'http://cdn.example.com/a.js' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.INSECURE);
});

test('blocks active tag without integrity', () => {
  const result = guard.evaluateSubresource({ tag: 'link', src: 'https://cdn.example.com/a.css' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.MISSING_INTEGRITY);
});

test('blocks weak md5 integrity', () => {
  const result = guard.evaluateSubresource({ tag: 'script', src: 'https://cdn.example.com/a.js', integrity: 'md5-abcdefghijklmnop' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.WEAK_ALGORITHM);
});

test('blocks url credentials', () => {
  const result = guard.evaluateSubresource({ tag: 'script', src: 'https://user:pass@cdn.example.com/a.js', integrity: 'sha384-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.CREDENTIALS);
});

