'use strict';

const test = require('node:test');
const assert = require('node:assert');

const guard = require('./cacheauthguard');

test('plain response without cache header is left alone', () => {
  const headers = { 'content-type': 'text/html' };
  const result = guard.applyAuthCacheGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(result.reason, guard.REASON.MISSING);
  assert.equal(headers['cache-control'], undefined);
});

test('set-cookie without cache header forces private no-store', () => {
  const headers = { 'set-cookie': ['sid=abc; HttpOnly'] };
  const result = guard.applyAuthCacheGuard(headers);
  assert.equal(result.changed, true);
  assert.equal(result.reason, guard.REASON.MISSING);
  assert.deepEqual(headers['cache-control'], ['private, no-store, max-age=0']);
});

test('set-cookie with public max-age is rewritten', () => {
  const headers = {
    'set-cookie': ['sid=abc'],
    'cache-control': 'public, max-age=600',
  };
  const result = guard.applyAuthCacheGuard(headers);
  assert.equal(result.changed, true);
  assert.equal(result.reason, guard.REASON.SHARED_CACHE);
  assert.deepEqual(headers['cache-control'], ['private, no-store, max-age=0']);
});

test('s-maxage forces rewrite', () => {
  const headers = {
    'cache-control': 's-maxage=120',
    'www-authenticate': 'Basic realm="x"',
  };
  const result = guard.applyAuthCacheGuard(headers);
  assert.equal(result.reason, guard.REASON.SHARED_CACHE);
  assert.deepEqual(headers['cache-control'], ['private, no-store, max-age=0']);
});

test('no-store is kept for set-cookie', () => {
  const headers = { 'set-cookie': ['sid=abc'], 'cache-control': 'no-store' };
  const result = guard.applyAuthCacheGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(headers['cache-control'], 'no-store');
});

test('private without no-store is kept', () => {
  const headers = { 'set-cookie': ['sid=abc'], 'cache-control': 'private, max-age=0' };
  const result = guard.applyAuthCacheGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(headers['cache-control'], 'private, max-age=0');
});

test('private scoped value is recognised', () => {
  const headers = { 'cache-control': 'private="Set-Cookie", max-age=60' };
  const result = guard.applyAuthCacheGuard(headers);
  assert.equal(result.changed, false);
});

test('public response stays cacheable', () => {
  const headers = { 'cache-control': 'public, max-age=3600' };
  const result = guard.applyAuthCacheGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(result.reason, guard.REASON.OK);
});

test('missing private on auth response rewrites', () => {
  const headers = { 'cache-control': 'max-age=0', 'set-cookie': ['sid=abc'] };
  const result = guard.applyAuthCacheGuard(headers);
  assert.equal(result.reason, guard.REASON.AUTH_CACHEABLE);
  assert.deepEqual(headers['cache-control'], ['private, no-store, max-age=0']);
});

test('expires is neutralised and age removed', () => {
  const headers = {
    'set-cookie': ['sid=abc'],
    'cache-control': 'public, max-age=600',
    expires: 'Wed, 21 Oct 2026 07:28:00 GMT',
    age: '12',
  };
  const result = guard.applyAuthCacheGuard(headers);
  assert.equal(result.changed, true);
  assert.deepEqual(headers.expires, ['Thu, 01 Jan 1970 00:00:00 GMT']);
  assert.equal(headers.age, undefined);
});

test('empty cache-control is rejected', () => {
  const headers = { 'cache-control': ' , ' };
  const result = guard.applyAuthCacheGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
  assert.deepEqual(headers['cache-control'], ['private, no-store, max-age=0']);
});

test('overlong cache-control is rejected', () => {
  const headers = { 'cache-control': 'x'.repeat(guard.MAX_VALUE_LENGTH + 1), 'set-cookie': ['sid=abc'] };
  const result = guard.applyAuthCacheGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
});

test('cacheDirectives splits and lowercases', () => {
  assert.deepEqual(guard.cacheDirectives('Public, MAX-AGE=60'), ['public', 'max-age=60']);
});

test('describeReason covers each branch', () => {
  assert.equal(guard.describeReason(guard.REASON.OK), '缓存策略安全');
  assert.equal(guard.describeReason('unknown'), '缓存策略安全');
});
