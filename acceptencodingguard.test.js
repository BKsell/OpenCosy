'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./acceptencodingguard');

function h(value) {
  return { 'accept-encoding': [value] };
}

test('缺头不改动', () => {
  const r = guard.applyAcceptEncodingGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('常规编码组合不改动', () => {
  const headers = h('gzip, deflate, br');
  const r = guard.applyAcceptEncodingGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('未知编码被剔除', () => {
  const headers = h('gzip, x-custom');
  const r = guard.applyAcceptEncodingGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_TOKEN);
  assert.strictEqual(headers['accept-encoding'], 'gzip');
});

test('越界权重被剔除', () => {
  const headers = h('gzip;q=2, br');
  const r = guard.applyAcceptEncodingGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_WEIGHT);
  assert.strictEqual(headers['accept-encoding'], 'br');
});

test('identity 零权重冲突被剔除', () => {
  const headers = h('identity;q=0, gzip');
  const r = guard.applyAcceptEncodingGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.IDENTITY_CONFLICT);
  assert.strictEqual(headers['accept-encoding'], 'gzip');
});

test('编码过多整体删除', () => {
  const headers = h('gzip,br,deflate,zstd,identity,*,gzip,br');
  const r = guard.applyAcceptEncodingGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
});

test('超长头删除', () => {
  const headers = h('gzip;q=0.5,'.repeat(40));
  const r = guard.applyAcceptEncodingGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});
