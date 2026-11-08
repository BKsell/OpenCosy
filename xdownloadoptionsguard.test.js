'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./xdownloadoptionsguard');

function h(value) {
  return { 'x-download-options': [value] };
}

test('缺头返回 missing', () => {
  const r = guard.applyXDownloadOptionsGuard({});
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('noopen 不改动', () => {
  const headers = h('noopen');
  const r = guard.applyXDownloadOptionsGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('大小写不敏感', () => {
  const headers = h('NoOpen');
  const r = guard.applyXDownloadOptionsGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('open 取值被剥除', () => {
  const headers = h('open');
  const r = guard.applyXDownloadOptionsGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.UNKNOWN_VALUE);
  assert.strictEqual(headers['x-download-options'], undefined);
});

test('未知取值被剥除', () => {
  const headers = h('inline');
  const r = guard.applyXDownloadOptionsGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.UNKNOWN_VALUE);
});

test('空取值视为非法', () => {
  const headers = h('   ');
  const r = guard.applyXDownloadOptionsGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers['x-download-options'], undefined);
});

test('多值冲突被剥除', () => {
  const headers = { 'x-download-options': ['noopen', 'open'] };
  const r = guard.applyXDownloadOptionsGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MULTIPLE_VALUES);
  assert.strictEqual(headers['x-download-options'], undefined);
});

test('控制字符被剥除', () => {
  const headers = h('noopen\u0007');
  const r = guard.applyXDownloadOptionsGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE_CHARS);
});

test('超长取值被剥除', () => {
  const headers = h(`noopen; ${'a'.repeat(80)}`);
  const r = guard.applyXDownloadOptionsGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
  assert.strictEqual(headers['x-download-options'], undefined);
});

test('describeReason 覆盖主要状态', () => {
  assert.strictEqual(typeof guard.describeReason(guard.REASON.OK), 'string');
  assert.strictEqual(typeof guard.describeReason('unknown'), 'string');
});
