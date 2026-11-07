'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./updatefeedguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows allowlisted https feed', () => {
  const result = guard.evaluateUpdateFeed({ url: 'https://updates.example.com/feed.json', allowHosts: ['*.example.com'] });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks plaintext feed', () => {
  const result = guard.evaluateUpdateFeed({ url: 'http://updates.example.com/feed.json', allowHosts: ['*.example.com'] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.PLAINTEXT);
});

test('blocks local feed', () => {
  const result = guard.evaluateUpdateFeed({ url: 'file:///etc/passwd' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.LOCAL_PATH);
});

test('blocks feed credentials', () => {
  const result = guard.evaluateUpdateFeed({ url: 'https://user:pass@updates.example.com/feed.json', allowHosts: ['*.example.com'] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.CREDENTIALS);
});

test('blocks host outside allowlist', () => {
  const result = guard.evaluateUpdateFeed({ url: 'https://evil.com/feed.json', allowHosts: ['*.example.com'] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.HOST_NOT_ALLOWED);
});

test('blocks unknown channel', () => {
  const result = guard.evaluateUpdateFeed({ url: 'https://updates.example.com/feed.json', allowHosts: ['*.example.com'], channel: 'dev' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.CHANNEL_MISMATCH);
});

