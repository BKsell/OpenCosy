'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./cookiepartitionguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows secure first party cookie', () => {
  const result = guard.evaluateCookie({ name: 'pref', secure: true, httpOnly: true, sameSite: 'lax' });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks insecure cookie', () => {
  const result = guard.evaluateCookie({ name: 'pref', secure: false });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.INSECURE_COOKIE);
});

test('blocks credential cookie without httpOnly', () => {
  const result = guard.evaluateCookie({ name: 'sessionid', secure: true, httpOnly: false, sameSite: 'lax' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.CREDENTIAL_COOKIE_HTTPONLY);
});

test('blocks wildcard domain', () => {
  const result = guard.evaluateCookie({ name: 'pref', secure: true, httpOnly: true, domain: '*example.com' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.WILDCARD_DOMAIN);
});

test('blocks unpartitioned third party cookie', () => {
  const result = guard.evaluateCookie({ name: 'pref', secure: true, httpOnly: true, domain: 'example.com', sameSite: 'lax' }, { initiatorSite: 'a.example', targetSite: 'b.example' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.THIRD_PARTY_UNPARTITIONED);
});

