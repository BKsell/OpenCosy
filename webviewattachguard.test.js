'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./webviewattachguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows https webview on allowed host', () => {
  const result = guard.evaluateWebview({ webviewTagEnabled: true, src: 'https://www.example.com/x' }, { allowHosts: ['*.example.com'] });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks disabled webview tag', () => {
  const result = guard.evaluateWebview({ webviewTagEnabled: false, src: 'https://www.example.com/x' }, { allowHosts: ['*.example.com'] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.TAG_DISABLED);
});

test('blocks missing src', () => {
  const result = guard.evaluateWebview({ webviewTagEnabled: true }, { allowHosts: ['*.example.com'] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.MISSING_SRC);
});

test('blocks plaintext webview', () => {
  const result = guard.evaluateWebview({ webviewTagEnabled: true, src: 'http://www.example.com/x' }, { allowHosts: ['*.example.com'] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.INSECURE_SRC);
});

test('blocks host outside allowlist', () => {
  const result = guard.evaluateWebview({ webviewTagEnabled: true, src: 'https://evil.com/x' }, { allowHosts: ['*.example.com'] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.HOST_NOT_ALLOWED);
});

test('blocks node integration', () => {
  const result = guard.evaluateWebview({ webviewTagEnabled: true, src: 'https://www.example.com/x', nodeIntegration: true }, { allowHosts: ['*.example.com'] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.NODE_EXPOSED);
});

