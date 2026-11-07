'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./contentlocationguard');

const page = { url: 'https://app.example.com/a/b' };

function h(value) {
  return { 'content-location': [value] };
}

test('无 Content-Location 时不变更', () => {
  const headers = { 'content-type': ['text/html'] };
  const r = guard.applyContentLocationGuard(headers, page);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('同源相对路径保留', () => {
  const headers = h('/a/b.html');
  const r = guard.applyContentLocationGuard(headers, page);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.strictEqual(r.target, 'https://app.example.com/a/b.html');
});

test('第三方绝对地址被移除', () => {
  const headers = h('https://cdn.other.net/copy.html');
  const r = guard.applyContentLocationGuard(headers, page);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.CROSS_ORIGIN);
  assert.strictEqual(headers['content-location'], undefined);
});

test('非 HTTP 协议被移除', () => {
  const headers = h('file:///etc/passwd');
  const r = guard.applyContentLocationGuard(headers, page);
  assert.strictEqual(r.reason, guard.REASON.BAD_SCHEME);
  assert.strictEqual(headers['content-location'], undefined);
});

test('超长值被移除', () => {
  const headers = h(`https://app.example.com/${'a'.repeat(guard.MAX_VALUE_LENGTH)}`);
  const r = guard.applyContentLocationGuard(headers, page);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers['content-location'], undefined);
});

test('控制字符被移除', () => {
  const headers = h('/a\u0001b');
  const r = guard.applyContentLocationGuard(headers, page);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('大小写不敏感键名被识别', () => {
  const headers = { 'Content-Location': ['https://evil.example/x'] };
  const r = guard.applyContentLocationGuard(headers, page);
  assert.strictEqual(r.reason, guard.REASON.CROSS_ORIGIN);
  assert.strictEqual(headers['Content-Location'], undefined);
});

test('describeReason 覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
