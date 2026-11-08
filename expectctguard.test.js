'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./expectctguard');

function h(value) {
  return { 'expect-ct': [value] };
}

test('缺头返回 missing 且不改动', () => {
  const headers = {};
  const r = guard.applyExpectCtGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('任何取值都被整头剥除', () => {
  const headers = h('max-age=3600, enforce');
  const r = guard.applyExpectCtGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.DEPRECATED);
  assert.strictEqual(headers['expect-ct'], undefined);
});

test('report-uri 被单独识别', () => {
  const r = guard.inspectExpectCt('max-age=60, report-uri="https://example.com/r"');
  assert.strictEqual(r.reason, guard.REASON.REPORT_URI_LEAK);
  assert.deepStrictEqual(r.directives, ['max-age=60']);
});

test('超长缓存时长被识别', () => {
  const r = guard.inspectExpectCt('max-age=999999');
  assert.strictEqual(r.reason, guard.REASON.UNSAFE_MAX_AGE);
  assert.deepStrictEqual(r.directives, []);
});

test('非数字缓存时长被识别', () => {
  const r = guard.inspectExpectCt('max-age=forever');
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('未知指令被识别', () => {
  const r = guard.inspectExpectCt('max-age=60, made-up');
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.deepStrictEqual(r.directives, ['max-age=60']);
});

test('合规取值返回 ok', () => {
  const r = guard.inspectExpectCt('max-age=60, enforce');
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.deepStrictEqual(r.directives, ['max-age=60', 'enforce']);
});

test('空值返回 malformed', () => {
  const r = guard.inspectExpectCt('   ');
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('超长返回 overlong', () => {
  const r = guard.inspectExpectCt('a'.repeat(600));
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});

test('头键大小写被正确处理', () => {
  const headers = { 'Expect-CT': ['max-age=0'] };
  const r = guard.applyExpectCtGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers['Expect-CT'], undefined);
});

test('描述覆盖所有状态', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
