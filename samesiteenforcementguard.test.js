'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./samesiteenforcementguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows same site request', () => {
  const result = guard.evaluateSameSiteRequest({ url: 'https://example.com/a', initiator: 'https://example.com/', method: 'POST' });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks strict cookie cross site', () => {
  const result = guard.evaluateSameSiteRequest({ url: 'https://other.com/a', initiator: 'https://example.com/', cookieSameSite: 'strict' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.CROSS_SITE_STRICT);
});

test('blocks lax unsafe method', () => {
  const result = guard.evaluateSameSiteRequest({ url: 'https://other.com/a', initiator: 'https://example.com/', cookieSameSite: 'lax', method: 'POST' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.CROSS_SITE_LAX_UNSAFE_METHOD);
});

test('blocks unspecified same site', () => {
  const result = guard.evaluateSameSiteRequest({ url: 'https://other.com/a', initiator: 'https://example.com/' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.MISSING_SAMESITE);
});

test('blocks https to http downgrade', () => {
  const result = guard.evaluateSameSiteRequest({ url: 'http://example.com/a', initiator: 'https://example.com/' });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.DOWNGRADE);
});

