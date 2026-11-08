'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./notificationpayloadguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows plain notification', () => {
  const result = guard.evaluateNotification({ title: 'Build complete', body: 'done' });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks empty notification', () => {
  const result = guard.evaluateNotification({});
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.EMPTY_TITLE);
});

test('blocks oversized body', () => {
  const result = guard.evaluateNotification({ title: 'x', body: new Array(5000).join('a') });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.TOO_LONG);
});

test('blocks script scheme in body', () => {
  const result = guard.evaluateNotification({ title: 'hi', body: 'javascript:alert(1)' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.MARKDOWN_INJECTION);
});

test('blocks data uri icon', () => {
  const result = guard.evaluateNotification({ title: 'hi', icon: 'data:image/png;base64,xx' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.ICON_DATA_URI);
});

test('blocks script action url', () => {
  const result = guard.evaluateNotification({ title: 'hi', actionUrl: 'javascript:alert(1)' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.ACTION_URL);
});

