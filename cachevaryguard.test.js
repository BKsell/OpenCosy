'use strict';

const nodeTest = require('node:test');
const assert = require('node:assert');
const guard = require('./cachevaryguard');

const { REASON, evaluateCacheVary, applyCacheVaryGuard, describeReason } = guard;

nodeTest.test('plain response needs no patch', () => {
  const verdict = evaluateCacheVary({ 'cache-control': ['max-age=60'] });
  assert.equal(verdict.action, 'allow');
  assert.equal(verdict.reason, REASON.OK);
});

nodeTest.test('origin-scoped CORS without Vary gets Vary: Origin', () => {
  const headers = { 'access-control-allow-origin': ['https://example.com'] };
  const result = applyCacheVaryGuard(headers);
  assert.equal(result.changed, true);
  assert.equal(result.verdict.reason, REASON.MISSING_VARY);
  assert.deepEqual(headers['Vary'], ['Origin']);
});

nodeTest.test('existing Vary is preserved and extended', () => {
  const headers = {
    'access-control-allow-origin': ['https://example.com'],
    vary: ['Accept-Encoding'],
  };
  applyCacheVaryGuard(headers);
  assert.deepEqual(headers['Vary'], ['Accept-Encoding, Origin']);
});

nodeTest.test('existing Vary: Origin is left alone', () => {
  const headers = {
    'access-control-allow-origin': ['https://example.com'],
    vary: ['origin'],
  };
  assert.equal(applyCacheVaryGuard(headers).changed, false);
});

nodeTest.test('wildcard CORS does not need Vary', () => {
  const headers = { 'access-control-allow-origin': ['*'] };
  assert.equal(evaluateCacheVary(headers).action, 'allow');
});

nodeTest.test('set-cookie without cache-control becomes no-store', () => {
  const headers = { 'set-cookie': ['sid=1; HttpOnly'] };
  const result = applyCacheVaryGuard(headers);
  assert.equal(result.verdict.reason, REASON.COOKIE_CACHEABLE);
  assert.deepEqual(headers['Cache-Control'], ['private, no-store']);
});

nodeTest.test('set-cookie with public becomes private', () => {
  const headers = { 'set-cookie': ['sid=1'], 'cache-control': ['public, max-age=600'] };
  const result = applyCacheVaryGuard(headers);
  assert.equal(result.verdict.reason, REASON.PUBLIC_WITH_COOKIE);
  assert.deepEqual(headers['Cache-Control'], ['private, no-store']);
});

nodeTest.test('set-cookie with private is accepted', () => {
  const headers = { 'set-cookie': ['sid=1'], 'cache-control': ['private, max-age=60'] };
  assert.equal(evaluateCacheVary(headers).action, 'allow');
});

nodeTest.test('set-cookie with no-store is accepted', () => {
  const headers = { 'set-cookie': ['sid=1'], 'cache-control': ['no-store'] };
  assert.equal(evaluateCacheVary(headers).action, 'allow');
});

nodeTest.test('header lookup is case insensitive', () => {
  const headers = { 'Access-Control-Allow-Origin': ['https://a.com'], 'VARY': ['Accept'] };
  assert.equal(evaluateCacheVary(headers).reason, REASON.MISSING_VARY);
});

nodeTest.test('string values are accepted', () => {
  const headers = { 'access-control-allow-origin': 'https://a.com' };
  assert.equal(evaluateCacheVary(headers).reason, REASON.MISSING_VARY);
});

nodeTest.test('apply reports no change on clean responses', () => {
  const headers = { 'cache-control': ['no-store'], vary: ['Origin'] };
  assert.equal(applyCacheVaryGuard(headers).changed, false);
});

nodeTest.test('describeReason covers every reason', () => {
  for (const reason of Object.values(REASON)) {
    assert.ok(describeReason(reason).length > 0, reason);
  }
});
