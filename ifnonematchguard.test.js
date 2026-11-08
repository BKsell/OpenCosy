'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./ifnonematchguard');

function h(value) {
  return { 'if-none-match': [value] };
}

test('缺头不改动', () => {
  const r = guard.applyIfNoneMatchGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('强弱标签混合合规', () => {
  const headers = h('"abc", W/"def"');
  const r = guard.applyIfNoneMatchGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('星号合规', () => {
  const headers = h('*');
  const r = guard.applyIfNoneMatchGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('未加引号标签被剔除', () => {
  const headers = h('abc, "def"');
  const r = guard.applyIfNoneMatchGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_TAG);
  assert.strictEqual(headers['if-none-match'], '"def"');
});

test('全部非法时删除', () => {
  const headers = h('abc');
  const r = guard.applyIfNoneMatchGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_TAG);
  assert.strictEqual(headers['if-none-match'], undefined);
});

test('超长头删除', () => {
  const headers = h('"x",'.repeat(300));
  const r = guard.applyIfNoneMatchGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});
