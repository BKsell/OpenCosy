'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./contentencodingbombguard');

test('普通 gzip 响应通过', () => {
  const r = guard.applyContentEncodingGuard({ 'content-encoding': 'gzip', 'content-length': '2048' });
  assert.strictEqual(r.changed, false);
  assert.deepStrictEqual(r.encodings, ['gzip']);
  assert.strictEqual(r.length, 2048);
});

test('无编码无长度通过', () => {
  const r = guard.inspectResponseBody({ 'content-type': 'text/html' });
  assert.strictEqual(r.ok, true);
});

test('空头被拒', () => {
  const r = guard.inspectResponseBody(null);
  assert.strictEqual(r.reason, guard.REASON.EMPTY);
});

test('base64 编码被拒', () => {
  const r = guard.inspectResponseBody({ 'content-encoding': 'base64' });
  assert.strictEqual(r.reason, guard.REASON.BASE64);
});

test('未知编码被拒', () => {
  const r = guard.inspectResponseBody({ 'content-encoding': 'compress' });
  assert.strictEqual(r.reason, guard.REASON.UNSUPPORTED);
});

test('多层编码被拒', () => {
  const r = guard.inspectResponseBody({ 'content-encoding': 'gzip, br, deflate' });
  assert.strictEqual(r.reason, guard.REASON.MULTIPLE);
});

test('非法长度被拒', () => {
  const r = guard.inspectResponseBody({ 'content-length': '12abc' });
  assert.strictEqual(r.reason, guard.REASON.BAD_LENGTH);
});

test('负长度被拒', () => {
  const r = guard.inspectResponseBody({ 'content-length': '-5' });
  assert.strictEqual(r.reason, guard.REASON.BAD_LENGTH);
});

test('超上限体积被拒', () => {
  const r = guard.inspectResponseBody({ 'content-length': String(guard.MAX_BYTES + 1) });
  assert.strictEqual(r.reason, guard.REASON.TOO_LARGE);
});

test('压缩响应缺长度被拒', () => {
  const r = guard.inspectResponseBody({ 'content-encoding': 'br' });
  assert.strictEqual(r.reason, guard.REASON.UNKNOWN_LENGTH);
});

test('自定义上限生效', () => {
  const r = guard.inspectResponseBody({ 'content-length': '1024' }, { maxBytes: 512 });
  assert.strictEqual(r.reason, guard.REASON.TOO_LARGE);
});

test('数组头取首值', () => {
  const r = guard.inspectResponseBody({ 'content-encoding': ['gzip', 'br'], 'content-length': ['10', '20'] });
  assert.strictEqual(r.ok, true);
  assert.deepStrictEqual(r.encodings, ['gzip']);
});

test('描述文本覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
