'use strict';

const test = require('node:test');
const assert = require('node:assert');

const guard = require('./frameoptionsguard');

test('missing header is reported without change', () => {
  const headers = {};
  const result = guard.applyFrameOptionsGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(result.reason, guard.REASON.MISSING);
});

test('deny is kept', () => {
  const headers = { 'X-Frame-Options': 'DENY' };
  const result = guard.applyFrameOptionsGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(result.reason, guard.REASON.OK);
  assert.equal(headers['X-Frame-Options'], 'DENY');
});

test('sameorigin is normalised but kept', () => {
  const headers = { 'x-frame-options': 'SAMEORIGIN' };
  const result = guard.applyFrameOptionsGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(headers['x-frame-options'], 'SAMEORIGIN');
});

test('allow-from is removed', () => {
  const headers = { 'x-frame-options': 'ALLOW-FROM https://example.com' };
  const result = guard.applyFrameOptionsGuard(headers);
  assert.equal(result.changed, true);
  assert.equal(result.reason, guard.REASON.ALLOW_FROM);
  assert.equal(headers['x-frame-options'], undefined);
});

test('allowall is removed', () => {
  const headers = { 'x-frame-options': 'ALLOWALL' };
  const result = guard.applyFrameOptionsGuard(headers);
  assert.equal(result.reason, guard.REASON.ALLOW_ALL);
  assert.equal(headers['x-frame-options'], undefined);
});

test('star is treated as allow all', () => {
  const headers = { 'x-frame-options': '*' };
  const result = guard.applyFrameOptionsGuard(headers);
  assert.equal(result.reason, guard.REASON.ALLOW_ALL);
  assert.equal(headers['x-frame-options'], undefined);
});

test('multiple values are removed', () => {
  const headers = { 'x-frame-options': ['DENY', 'SAMEORIGIN'] };
  const result = guard.applyFrameOptionsGuard(headers);
  assert.equal(result.reason, guard.REASON.MULTIPLE_VALUES);
  assert.equal(headers['x-frame-options'], undefined);
});

test('comma joined value is removed', () => {
  const headers = { 'x-frame-options': 'DENY, SAMEORIGIN' };
  const result = guard.applyFrameOptionsGuard(headers);
  assert.equal(result.reason, guard.REASON.MULTIPLE_VALUES);
  assert.equal(headers['x-frame-options'], undefined);
});

test('csp frame-ancestors conflict drops xfo', () => {
  const headers = {
    'x-frame-options': 'DENY',
    'content-security-policy': "default-src 'none'; frame-ancestors 'self'",
  };
  const result = guard.applyFrameOptionsGuard(headers);
  assert.equal(result.reason, guard.REASON.CSP_CONFLICT);
  assert.equal(headers['x-frame-options'], undefined);
  assert.equal(headers['content-security-policy'], "default-src 'none'; frame-ancestors 'self'");
});

test('csp without frame-ancestors keeps xfo', () => {
  const headers = {
    'x-frame-options': 'DENY',
    'content-security-policy': "default-src 'self'",
  };
  const result = guard.applyFrameOptionsGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(headers['x-frame-options'], 'DENY');
});

test('unknown token is removed', () => {
  const headers = { 'x-frame-options': 'NONE' };
  const result = guard.applyFrameOptionsGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
  assert.equal(headers['x-frame-options'], undefined);
});

test('empty value is removed', () => {
  const headers = { 'x-frame-options': '   ' };
  const result = guard.applyFrameOptionsGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
  assert.equal(headers['x-frame-options'], undefined);
});

test('describeReason covers each branch', () => {
  assert.equal(guard.describeReason(guard.REASON.OK), 'X-Frame-Options 有效');
  assert.equal(guard.describeReason('other'), 'X-Frame-Options 有效');
});
