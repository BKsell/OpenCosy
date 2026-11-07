'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./xdnsprefetchguard');

function h(value) {
  return { 'X-DNS-Prefetch-Control': value };
}

test('off 不改动', () => {
  const headers = h('off');
  const r = guard.applyDnsPrefetchGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.strictEqual(headers['X-DNS-Prefetch-Control'], 'off');
});

test('大写 OFF 放行', () => {
  const headers = h('OFF');
  const r = guard.applyDnsPrefetchGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('缺少头返回 missing', () => {
  const r = guard.applyDnsPrefetchGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
  assert.strictEqual(r.changed, false);
});

test('on 被关闭', () => {
  const headers = h('on');
  const r = guard.applyDnsPrefetchGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.ENABLED);
  assert.strictEqual(headers['X-DNS-Prefetch-Control'], 'off');
});

test('非法取值被关闭', () => {
  const headers = h('auto');
  const r = guard.applyDnsPrefetchGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers['X-DNS-Prefetch-Control'], 'off');
});

test('超长取值被关闭', () => {
  const headers = h('o'.repeat(guard.MAX_VALUE_LENGTH + 4));
  const r = guard.applyDnsPrefetchGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});

test('重复下发被收敛', () => {
  const headers = { 'X-DNS-Prefetch-Control': ['on', 'off'] };
  const r = guard.applyDnsPrefetchGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MULTI_VALUE);
  assert.strictEqual(headers['X-DNS-Prefetch-Control'], 'off');
});

test('小写键名命中', () => {
  const headers = { 'x-dns-prefetch-control': 'on' };
  const r = guard.applyDnsPrefetchGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers['x-dns-prefetch-control'], 'off');
});

test('空白值被关闭', () => {
  const headers = h('   ');
  const r = guard.applyDnsPrefetchGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('describeReason 覆盖分支', () => {
  assert.match(guard.describeReason(guard.REASON.MALFORMED), /非法/);
  assert.match(guard.describeReason(guard.REASON.OVERLONG), /超长/);
  assert.match(guard.describeReason(guard.REASON.MULTI_VALUE), /重复/);
  assert.match(guard.describeReason(guard.REASON.ENABLED), /预取/);
  assert.match(guard.describeReason(guard.REASON.OK), /关闭/);
});
