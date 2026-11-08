'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./acacguard');

test('缺头不改动', () => {
  const r = guard.applyAcacGuard({});
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('指定来源加凭据合规', () => {
  const headers = {
    'access-control-allow-origin': 'https://app.example.com',
    'access-control-allow-credentials': 'true',
  };
  const r = guard.applyAcacGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('通配来源加凭据被移除', () => {
  const headers = {
    'access-control-allow-origin': '*',
    'access-control-allow-credentials': 'true',
  };
  const r = guard.applyAcacGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.WILDCARD_CREDENTIALS);
  assert.strictEqual(headers['access-control-allow-credentials'], undefined);
});

test('非法凭据取值被移除', () => {
  const headers = {
    'access-control-allow-origin': 'https://app.example.com',
    'access-control-allow-credentials': 'yes',
  };
  const r = guard.applyAcacGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['access-control-allow-credentials'], undefined);
});
