'use strict';

const test = require('node:test');
const assert = require('node:assert');

const guard = require('./xssprotectionguard');

test('missing header is untouched', () => {
  const headers = {};
  const result = guard.applyXSSProtectionGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(result.reason, guard.REASON.MISSING);
});

test('legacy enabled header is removed', () => {
  const headers = { 'x-xss-protection': '1; mode=block' };
  const result = guard.applyXSSProtectionGuard(headers);
  assert.equal(result.changed, true);
  assert.equal(result.reason, guard.REASON.LEGACY_ENABLED);
  assert.equal(headers['x-xss-protection'], undefined);
});

test('legacy disabled header is removed', () => {
  const headers = { 'X-XSS-Protection': '0' };
  const result = guard.applyXSSProtectionGuard(headers);
  assert.equal(result.reason, guard.REASON.LEGACY_DISABLED);
  assert.equal(headers['X-XSS-Protection'], undefined);
});

test('unknown value is removed as malformed', () => {
  const headers = { 'x-xss-protection': 'sanitize' };
  const result = guard.applyXSSProtectionGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
  assert.equal(headers['x-xss-protection'], undefined);
});

test('empty value is removed', () => {
  const headers = { 'x-xss-protection': ' ' };
  const result = guard.applyXSSProtectionGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
  assert.equal(headers['x-xss-protection'], undefined);
});

test('array header is handled', () => {
  const headers = { 'x-xss-protection': ['1', '0'] };
  const result = guard.applyXSSProtectionGuard(headers);
  assert.equal(result.changed, true);
  assert.equal(headers['x-xss-protection'], undefined);
});

test('inspect does not mutate headers', () => {
  const headers = { 'x-xss-protection': '1' };
  const result = guard.inspectXSSProtection(headers);
  assert.equal(result.reason, guard.REASON.LEGACY_ENABLED);
  assert.equal(headers['x-xss-protection'], '1');
});

test('describeReason covers branches', () => {
  assert.equal(guard.describeReason(guard.REASON.MISSING), '响应未声明旧版 XSS 过滤器');
  assert.equal(guard.describeReason('other'), '旧版 XSS 过滤器已清理');
});
