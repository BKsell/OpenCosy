'use strict';

const test = require('node:test');
const assert = require('node:assert');

const guard = require('./permissionspolicyguard');

test('missing header reports missing without change', () => {
  const headers = { 'content-type': 'text/html' };
  const result = guard.applyPermissionsPolicyGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(result.reason, guard.REASON.MISSING);
  assert.equal(headers['content-type'], 'text/html');
});

test('valid policy is kept untouched', () => {
  const headers = { 'Permissions-Policy': 'camera=(self), geolocation=(self "https://maps.example")' };
  const result = guard.applyPermissionsPolicyGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(result.reason, guard.REASON.OK);
  assert.equal(headers['Permissions-Policy'], 'camera=(self), geolocation=(self "https://maps.example")');
});

test('wildcard camera grant is removed', () => {
  const headers = { 'permissions-policy': 'camera=*, microphone=(self), geolocation=()' };
  const result = guard.applyPermissionsPolicyGuard(headers);
  assert.equal(result.changed, true);
  assert.equal(result.reason, guard.REASON.WILDCARD_GRANT);
  assert.deepEqual(result.removed, ['camera']);
  assert.deepEqual(headers['permissions-policy'], ['microphone=(self), geolocation=()']);
});

test('empty allowlist means deny and is kept', () => {
  const headers = { 'permissions-policy': 'usb=(), serial=(), hid=()' };
  const result = guard.applyPermissionsPolicyGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(headers['permissions-policy'], 'usb=(), serial=(), hid=()');
});

test('all directives broad removes the header', () => {
  const headers = { 'permissions-policy': 'camera=*, microphone=*, geolocation=*' };
  const result = guard.applyPermissionsPolicyGuard(headers);
  assert.equal(result.changed, true);
  assert.equal(headers['permissions-policy'], undefined);
});

test('malformed policy is dropped entirely', () => {
  const headers = { 'permissions-policy': 'camera=(self' };
  const result = guard.applyPermissionsPolicyGuard(headers);
  assert.equal(result.changed, true);
  assert.equal(result.reason, guard.REASON.MALFORMED);
  assert.equal(headers['permissions-policy'], undefined);
});

test('overlong policy is dropped', () => {
  const headers = { 'permissions-policy': 'camera=(' + 'a'.repeat(guard.MAX_VALUE_LENGTH) + ')' };
  const result = guard.applyPermissionsPolicyGuard(headers);
  assert.equal(result.changed, true);
  assert.equal(result.reason, guard.REASON.TOO_LONG);
  assert.equal(headers['permissions-policy'], undefined);
});

test('too many directives are rejected', () => {
  const names = [];
  for (let i = 0; i < guard.MAX_FEATURES + 4; i += 1) {
    names.push('feature-' + String(i) + '=(self)');
  }
  const headers = { 'permissions-policy': names.join(', ') };
  const result = guard.applyPermissionsPolicyGuard(headers);
  assert.equal(result.changed, true);
  assert.equal(result.reason, guard.REASON.TOO_MANY);
  assert.equal(headers['permissions-policy'], undefined);
});

test('invalid feature name is rejected', () => {
  const headers = { 'permissions-policy': 'Camera=(self)' };
  const result = guard.applyPermissionsPolicyGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
  assert.equal(headers['permissions-policy'], undefined);
});

test('array header value uses first entry', () => {
  const headers = { 'Permissions-Policy': ['camera=*, geolocation=(self)'] };
  const result = guard.applyPermissionsPolicyGuard(headers);
  assert.equal(result.changed, true);
  assert.deepEqual(result.removed, ['camera']);
  assert.deepEqual(headers['Permissions-Policy'], ['geolocation=(self)']);
});

test('splitDirectives respects quoted commas', () => {
  const parts = guard.splitDirectives('geolocation=("https://a.example, https://b.example")');
  assert.equal(parts.length, 1);
});

test('describeReason covers each branch', () => {
  assert.equal(guard.describeReason(guard.REASON.WILDCARD_GRANT), '站点把敏感能力授予任意来源');
  assert.equal(guard.describeReason(guard.REASON.OK), '权限策略有效');
  assert.equal(guard.describeReason('unknown'), '权限策略有效');
});
