'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./secfetchdestguard');

test('缺头不改动', () => {
  const r = guard.applySecFetchDestGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('script 合规', () => {
  const headers = { 'sec-fetch-dest': 'script' };
  const r = guard.applySecFetchDestGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('未知目标删除', () => {
  const headers = { 'sec-fetch-dest': 'executable' };
  const r = guard.applySecFetchDestGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.UNKNOWN);
  assert.strictEqual(headers['sec-fetch-dest'], undefined);
});

test('多值删除', () => {
  const headers = { 'sec-fetch-dest': ['script', 'style'] };
  const r = guard.applySecFetchDestGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
});

test('空值删除', () => {
  const headers = { 'sec-fetch-dest': '' };
  const r = guard.applySecFetchDestGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});

test('document 合规', () => {
  const headers = { 'sec-fetch-dest': 'DOCUMENT' };
  const r = guard.applySecFetchDestGuard(headers);
  assert.strictEqual(r.changed, false);
});
