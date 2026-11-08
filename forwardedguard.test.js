'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./forwardedguard');

function h(value) {
  return { forwarded: [value] };
}

test('缺头不改动', () => {
  const r = guard.applyForwardedGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合规代理链不改动', () => {
  const headers = h('for=192.0.2.10;proto=https, for="[2001:db8::1]"');
  const r = guard.applyForwardedGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('非法协议被剔除', () => {
  const headers = h('for=192.0.2.10;proto=ftp');
  const r = guard.applyForwardedGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_PROTO);
  assert.strictEqual(headers.forwarded, 'for=192.0.2.10');
});

test('穿越主机名被剔除', () => {
  const headers = h('for=192.0.2.10;host=evil..example.com');
  const r = guard.applyForwardedGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_HOST);
  assert.strictEqual(headers.forwarded, 'for=192.0.2.10');
});

test('非法节点被剔除', () => {
  const headers = h('for=unknown;for=@bad');
  const r = guard.applyForwardedGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_NODE);
  assert.strictEqual(headers.forwarded, 'for=unknown');
});

test('条目过多整体删除', () => {
  const headers = h('for=1.1.1.1, for=2.2.2.2, for=3.3.3.3, for=4.4.4.4');
  const r = guard.applyForwardedGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
  assert.strictEqual(headers.forwarded, undefined);
});

test('超长头删除', () => {
  const headers = h('for=' + '1'.repeat(600));
  const r = guard.applyForwardedGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
  assert.strictEqual(headers.forwarded, undefined);
});
