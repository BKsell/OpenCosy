'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./ageclockguard');

const NOW = Date.UTC(2026, 10, 7, 8, 0, 0);
const DATE_OK = new Date(NOW).toUTCString();

function h(age, date) {
  const headers = { Age: String(age) };
  if (date !== undefined) headers.Date = date;
  return headers;
}

test('合法 Age 不改动', () => {
  const headers = h(120, DATE_OK);
  const r = guard.applyAgeClockGuard(headers, NOW);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.strictEqual(headers.Age, '120');
});

test('缺少 Age 返回 missing', () => {
  const r = guard.applyAgeClockGuard({ Date: DATE_OK }, NOW);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
  assert.strictEqual(r.changed, false);
});

test('负数 Age 被剥除', () => {
  const headers = h('-5');
  const r = guard.applyAgeClockGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.NEGATIVE_AGE);
  assert.strictEqual(headers.Age, undefined);
});

test('带符号 Age 被剥除', () => {
  const headers = h('+30');
  const r = guard.applyAgeClockGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.NEGATIVE_AGE);
});

test('非数字 Age 被剥除', () => {
  const headers = h('abc');
  const r = guard.applyAgeClockGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('小数 Age 被剥除', () => {
  const headers = h('1.5');
  const r = guard.applyAgeClockGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('空串 Age 视为缺失', () => {
  const headers = h('');
  const r = guard.applyAgeClockGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('超出上限的 Age 被剥除', () => {
  const headers = h(guard.MAX_AGE_SECONDS + 1);
  const r = guard.applyAgeClockGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});

test('上限内的陈旧值先按 stale 处理', () => {
  const headers = h(guard.MAX_STALE_SECONDS);
  const r = guard.applyAgeClockGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('未来 Date 触发时钟偏移', () => {
  const future = new Date(NOW + 600000).toUTCString();
  const headers = h(10, future);
  const r = guard.applyAgeClockGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.DATE_SKEW);
  assert.strictEqual(headers.Age, undefined);
});

test('偏差预算内的 Date 放行', () => {
  const slight = new Date(NOW + 60000).toUTCString();
  const headers = h(10, slight);
  const r = guard.applyAgeClockGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('陈旧 Age 被剥除', () => {
  const headers = h(guard.MAX_STALE_SECONDS + 100, DATE_OK);
  const r = guard.applyAgeClockGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.STALE);
});

test('Date 无法解析时忽略该维度', () => {
  const headers = h(10, 'not-a-date');
  const r = guard.applyAgeClockGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('小写键名命中被剥除', () => {
  const headers = { age: '-1', date: DATE_OK };
  const r = guard.applyAgeClockGuard(headers, NOW);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers.age, undefined);
});

test('数组 Age 取首项判定', () => {
  const headers = { Age: ['30', '60'], Date: DATE_OK };
  const r = guard.applyAgeClockGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('describeReason 覆盖分支', () => {
  assert.match(guard.describeReason(guard.REASON.MALFORMED), /十进制/);
  assert.match(guard.describeReason(guard.REASON.OVERLONG), /合法区间/);
  assert.match(guard.describeReason(guard.REASON.NEGATIVE_AGE), /负值/);
  assert.match(guard.describeReason(guard.REASON.DATE_SKEW), /偏差/);
  assert.match(guard.describeReason(guard.REASON.STALE), /过期/);
  assert.match(guard.describeReason(guard.REASON.OK), /通过/);
});
