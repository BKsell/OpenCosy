'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./keepaliveguard');

function h(value) {
  return { 'Keep-Alive': value };
}

test('合法参数不改动', () => {
  const headers = h('timeout=30, max=100');
  const r = guard.applyKeepAliveGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.strictEqual(r.timeout, 30);
  assert.strictEqual(r.max, 100);
});

test('仅 timeout 放行', () => {
  const headers = h('timeout=5');
  const r = guard.applyKeepAliveGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.strictEqual(r.max, null);
});

test('缺少头返回 missing', () => {
  const r = guard.applyKeepAliveGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('缺少等号被剥除', () => {
  const headers = h('timeout');
  const r = guard.applyKeepAliveGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers['Keep-Alive'], undefined);
});

test('未知参数被剥除', () => {
  const headers = h('timeout=30, foo=1');
  const r = guard.applyKeepAliveGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('重复参数被剥除', () => {
  const headers = h('timeout=30, timeout=10');
  const r = guard.applyKeepAliveGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE_PARAM);
});

test('非数字取值被剥除', () => {
  const headers = h('timeout=abc');
  const r = guard.applyKeepAliveGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('超时超出预算被剥除', () => {
  const headers = h(`timeout=${guard.MAX_TIMEOUT + 1}`);
  const r = guard.applyKeepAliveGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TIMEOUT_RANGE);
  assert.strictEqual(headers['Keep-Alive'], undefined);
});

test('请求上限超预算被剥除', () => {
  const headers = h(`max=${guard.MAX_REQUESTS + 1}`);
  const r = guard.applyKeepAliveGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MAX_RANGE);
});

test('参数过多被剥除', () => {
  const headers = h('timeout=1, max=2, extra=3, tail=4');
  const r = guard.applyKeepAliveGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('超长字段被剥除', () => {
  const headers = h('timeout=' + '1'.repeat(guard.MAX_VALUE_LENGTH));
  const r = guard.applyKeepAliveGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});

test('小写键名命中', () => {
  const headers = { 'keep-alive': 'timeout=abc' };
  const r = guard.applyKeepAliveGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers['keep-alive'], undefined);
});

test('数组取值取首项', () => {
  const headers = { 'Keep-Alive': ['timeout=30', 'timeout=60'] };
  const r = guard.applyKeepAliveGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('describeReason 覆盖分支', () => {
  assert.match(guard.describeReason(guard.REASON.MALFORMED), /语法/);
  assert.match(guard.describeReason(guard.REASON.OVERLONG), /超长/);
  assert.match(guard.describeReason(guard.REASON.TIMEOUT_RANGE), /超时/);
  assert.match(guard.describeReason(guard.REASON.MAX_RANGE), /请求上限/);
  assert.match(guard.describeReason(guard.REASON.DUPLICATE_PARAM), /重复/);
  assert.match(guard.describeReason(guard.REASON.OK), /通过/);
});
