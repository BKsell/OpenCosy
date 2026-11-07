'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./setcookieattrguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows hardened cookie', () => {
  const result = guard.evaluateSetCookie('sid=abc; Secure; HttpOnly; SameSite=Lax');
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks insecure cookie', () => {
  const result = guard.evaluateSetCookie('sid=abc; HttpOnly; SameSite=Lax');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.NO_SECURE);
});

test('blocks cookie without httponly', () => {
  const result = guard.evaluateSetCookie('sid=abc; Secure; SameSite=Lax');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.NO_HTTPONLY);
});

test('blocks prefix mismatch', () => {
  const result = guard.evaluateSetCookie('__Host-sid=abc; Secure; HttpOnly');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.PREFIX_MISMATCH);
});

test('blocks expiry conflict', () => {
  const result = guard.evaluateSetCookie('sid=abc; Secure; HttpOnly; Max-Age=60; Expires=Wed, 21 Oct 2026 07:28:00 GMT');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.EXPIRY_CONFLICT);
});

test('blocks broad domain', () => {
  const result = guard.evaluateSetCookie('sid=abc; Secure; HttpOnly; Domain=com');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.DOMAIN_TOO_BROAD);
});

