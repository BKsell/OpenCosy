'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./ifmatchguard');

const ETAG = '"abc123"';

test('缺头不改动', () => {
  const r = guard.applyIfMatchGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('强 ETag 合规', () => {
  const headers = { 'if-match': ETAG };
  const r = guard.applyIfMatchGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('弱 ETag 合规', () => {
  const headers = { 'if-match': `W/${ETAG}` };
  const r = guard.applyIfMatchGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('通配符单独合规', () => {
  const headers = { 'if-match': '*' };
  const r = guard.applyIfMatchGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('通配符与 ETag 混用删除', () => {
  const headers = { 'if-match': `*, ${ETAG}` };
  const r = guard.applyIfMatchGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.WILDCARD_MIXED);
  assert.strictEqual(headers['if-match'], undefined);
});

test('未加引号删除', () => {
  const headers = { 'if-match': 'abc123' };
  const r = guard.applyIfMatchGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});

test('超长列表截断', () => {
  const tags = Array.from({ length: 20 }, (_, i) => `"t${i}"`);
  const headers = { 'if-match': tags.join(', ') };
  const r = guard.applyIfMatchGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
  assert.strictEqual(headers['if-match'].split(',').length, 16);
});

test('空值删除', () => {
  const headers = { 'if-match': '   ' };
  const r = guard.applyIfMatchGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});
