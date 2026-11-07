'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./sourcedmapguard');

test('缺头不改动', () => {
  const r = guard.applySourceMapGuard({});
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('站内相对路径保留', () => {
  const headers = { sourcemap: ['/assets/app.js.map'] };
  const r = guard.applySourceMapGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('外链 sourcemap 被删除', () => {
  const headers = { sourcemap: ['https://cdn.example.com/app.js.map'] };
  const r = guard.applySourceMapGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.EXTERNAL);
  assert.strictEqual(headers.sourcemap, undefined);
});

test('data URI 被删除', () => {
  const headers = { 'x-sourcemap': ['data:application/json;base64,AAAA'] };
  const r = guard.applySourceMapGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DATA_URI);
  assert.strictEqual(headers['x-sourcemap'], undefined);
});

test('穿越路径被删除', () => {
  const headers = { sourcemap: ['/assets/../secret.map'] };
  const r = guard.applySourceMapGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_PATH);
});

test('超长路径被删除', () => {
  const headers = { sourcemap: ['/' + 'a'.repeat(600)] };
  const r = guard.applySourceMapGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});
