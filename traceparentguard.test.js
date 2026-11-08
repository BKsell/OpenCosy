'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./traceparentguard');

const VALID = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';

test('缺头不改动', () => {
  const r = guard.applyTraceparentGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合规 traceparent 保留', () => {
  const headers = { traceparent: [VALID] };
  const r = guard.applyTraceparentGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('段数不足被删除', () => {
  const headers = { traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736' };
  const r = guard.applyTraceparentGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_FORMAT);
  assert.strictEqual(headers.traceparent, undefined);
});

test('全零 trace 被删除', () => {
  const headers = { traceparent: '00-' + '0'.repeat(32) + '-00f067aa0ba902b7-01' };
  const r = guard.applyTraceparentGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.ALL_ZERO);
});

test('非法 flags 被删除', () => {
  const headers = { traceparent: VALID.replace(/-01$/, '-zz') };
  const r = guard.applyTraceparentGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_FLAGS);
});

test('超长头删除', () => {
  const headers = { traceparent: VALID + '-' + 'a'.repeat(200) };
  const r = guard.applyTraceparentGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});
