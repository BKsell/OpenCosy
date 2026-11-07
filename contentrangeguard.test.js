'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./contentrangeguard');

function h(value, extra) {
  const headers = { 'content-range': [value] };
  if (extra !== undefined) headers['content-length'] = [String(extra)];
  return headers;
}

test('合法区间不改动', () => {
  const r = guard.applyContentRangeGuard(h('bytes 0-1023/4096', 1024));
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('未知总长不剥除但标记', () => {
  const headers = h('bytes 0-99/*', 100);
  const r = guard.applyContentRangeGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.UNKNOWN_TOTAL);
  assert.ok(headers['content-range']);
});

test('缺少头时返回 missing', () => {
  const r = guard.applyContentRangeGuard({});
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('无单位前缀视为非法并剥除', () => {
  const headers = h('0-1023/4096');
  const r = guard.applyContentRangeGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers['content-range'], undefined);
});

test('起止颠倒被剥除', () => {
  const headers = h('bytes 500-100/4096');
  const r = guard.applyContentRangeGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_ORDER);
  assert.strictEqual(headers['content-range'], undefined);
});

test('末字节等于总长视为矛盾', () => {
  const headers = h('bytes 0-4096/4096');
  const r = guard.applyContentRangeGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_TOTAL);
  assert.strictEqual(headers['content-range'], undefined);
});

test('超出安全整数被剥除', () => {
  const headers = h('bytes 0-9999999999999999/9999999999999999');
  const r = guard.applyContentRangeGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
  assert.strictEqual(headers['content-range'], undefined);
});

test('超长头被剥除', () => {
  const headers = h('bytes 0-1/' + '9'.repeat(200));
  const r = guard.applyContentRangeGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
  assert.strictEqual(headers['content-range'], undefined);
});

test('不可满足区间被剥除', () => {
  const headers = h('bytes */4096');
  const r = guard.applyContentRangeGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.UNSATISFIABLE);
  assert.strictEqual(headers['content-range'], undefined);
});

test('Content-Length 与区间长度不一致被剥除', () => {
  const headers = h('bytes 0-1023/4096', 2048);
  const r = guard.applyContentRangeGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.LENGTH_MISMATCH);
  assert.strictEqual(headers['content-range'], undefined);
});

test('Content-Length 非数字按不一致处理', () => {
  const headers = h('bytes 0-1023/4096', '1e3');
  const r = guard.applyContentRangeGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.LENGTH_MISMATCH);
  assert.strictEqual(headers['content-range'], undefined);
});

test('大小写不敏感键名被删除', () => {
  const headers = { 'Content-Range': ['bytes 0-9/20'] };
  const r = guard.applyContentRangeGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('数组外的字符串头也能解析', () => {
  const r = guard.inspectContentRange({ 'content-range': 'bytes 10-19/100' });
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.strictEqual(r.verdict.start, 10);
});

test('空格容忍', () => {
  const r = guard.inspectContentRange(h('  bytes   0 - 9 / 20  '));
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('describeReason 覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
