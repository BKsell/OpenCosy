'use strict';

const nodeTest = require('node:test');
const assert = require('node:assert');
const guard = require('./corsmisconfigguard');

const { REASON, evaluateCors, applyCorsGuard, describeReason } = guard;

nodeTest.test('plain response without CORS headers is untouched', () => {
  const headers = { 'content-type': ['text/html'] };
  const verdict = evaluateCors(headers);
  assert.equal(verdict.action, 'allow');
  assert.equal(verdict.reason, REASON.OK);
  assert.equal(applyCorsGuard(headers).changed, false);
});

nodeTest.test('single explicit origin with credentials is allowed', () => {
  const verdict = evaluateCors({
    'access-control-allow-origin': ['https://example.com'],
    'access-control-allow-credentials': ['true'],
  });
  assert.equal(verdict.action, 'allow');
});

nodeTest.test('wildcard with credentials drops credentials', () => {
  const verdict = evaluateCors({
    'Access-Control-Allow-Origin': ['*'],
    'Access-Control-Allow-Credentials': ['true'],
  });
  assert.equal(verdict.action, 'strip');
  assert.equal(verdict.reason, REASON.WILDCARD_CREDENTIALS);
  assert.deepEqual(verdict.strip, ['Access-Control-Allow-Credentials']);
});

nodeTest.test('wildcard without credentials is allowed', () => {
  assert.equal(evaluateCors({ 'access-control-allow-origin': ['*'] }).action, 'allow');
});

nodeTest.test('null origin is stripped', () => {
  const verdict = evaluateCors({ 'access-control-allow-origin': ['null'] });
  assert.equal(verdict.reason, REASON.NULL_ORIGIN);
  assert.ok(verdict.strip.includes('Access-Control-Allow-Credentials'));
});

nodeTest.test('multiple origins are stripped', () => {
  const verdict = evaluateCors({ 'access-control-allow-origin': ['https://a.com', 'https://b.com'] });
  assert.equal(verdict.reason, REASON.MULTIPLE_ORIGINS);
  assert.ok(verdict.strip.includes('Access-Control-Allow-Origin'));
});

nodeTest.test('credentials without origin is stripped', () => {
  const verdict = evaluateCors({ 'access-control-allow-credentials': ['true'] });
  assert.equal(verdict.reason, REASON.CREDENTIALS_WITHOUT_ORIGIN);
});

nodeTest.test('TRACE in allow-methods is removed but other methods kept', () => {
  const headers = {
    'access-control-allow-origin': ['https://example.com'],
    'access-control-allow-methods': ['GET, TRACE, POST'],
  };
  const result = applyCorsGuard(headers);
  assert.equal(result.changed, true);
  assert.equal(result.verdict.reason, REASON.TRACE_METHOD);
  assert.deepEqual(headers['Access-Control-Allow-Methods'], ['GET, POST']);
});

nodeTest.test('only TRACE method leaves header removed', () => {
  const headers = { 'access-control-allow-methods': ['TRACE'] };
  applyCorsGuard(headers);
  assert.equal(headers['Access-Control-Allow-Methods'], undefined);
});

nodeTest.test('sensitive exposed header is filtered', () => {
  const headers = { 'access-control-expose-headers': ['Set-Cookie, X-Trace-Id, Authorization'] };
  applyCorsGuard(headers);
  assert.deepEqual(headers['Access-Control-Expose-Headers'], ['X-Trace-Id']);
});

nodeTest.test('private network allowance is stripped', () => {
  const verdict = evaluateCors({ 'access-control-allow-private-network': ['true'] });
  assert.equal(verdict.reason, REASON.PRIVATE_NETWORK);
});

nodeTest.test('header lookup is case insensitive', () => {
  assert.equal(evaluateCors({ 'ACCESS-CONTROL-ALLOW-ORIGIN': 'null' }).reason, REASON.NULL_ORIGIN);
});

nodeTest.test('string header values are accepted', () => {
  const verdict = evaluateCors({ 'access-control-allow-origin': 'null' });
  assert.equal(verdict.reason, REASON.NULL_ORIGIN);
});

nodeTest.test('apply removes headers case-insensitively', () => {
  const headers = { 'access-control-allow-origin': ['null'], 'Access-Control-Allow-Credentials': ['true'] };
  applyCorsGuard(headers);
  assert.equal(Object.keys(headers).length, 0);
});

nodeTest.test('describeReason covers every reason', () => {
  for (const reason of Object.values(REASON)) {
    assert.equal(typeof describeReason(reason), 'string');
    assert.notEqual(describeReason(reason).length, 0, reason);
  }
});
