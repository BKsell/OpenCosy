'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./filesystemaccessguard');

test('空地址视为非法', () => {
  const r = guard.inspectFileSystemAccess('');
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('非法 URL 视为非法', () => {
  const r = guard.inspectFileSystemAccess('not a url');
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('HTTPS 来源允许', () => {
  const r = guard.inspectFileSystemAccess('https://example.com/app');
  assert.strictEqual(r.allowed, true);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('本地 HTTP 允许', () => {
  const r = guard.inspectFileSystemAccess('http://localhost:5173/index.html');
  assert.strictEqual(r.allowed, true);
});

test('远程 HTTP 拒绝', () => {
  const r = guard.inspectFileSystemAccess('http://example.com/app');
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE_SCHEME);
});

test('file 协议拒绝', () => {
  const r = guard.inspectFileSystemAccess('file:///C:/Windows/System32');
  assert.strictEqual(r.allowed, false);
});

test('data 协议视为不透明来源', () => {
  const r = guard.inspectFileSystemAccess('data:text/html,<script>alert(1)</script>');
  assert.strictEqual(r.reason, guard.REASON.OPAQUE_ORIGIN);
});

test('blob 协议视为不透明来源', () => {
  const r = guard.inspectFileSystemAccess('blob:https://example.com/uuid');
  assert.strictEqual(r.reason, guard.REASON.OPAQUE_ORIGIN);
});

test('内嵌凭据拒绝', () => {
  const r = guard.inspectFileSystemAccess('https://user:pass@example.com/app');
  assert.strictEqual(r.reason, guard.REASON.EMBEDDED_CREDENTIALS);
});

test('路径穿越拒绝', () => {
  const r = guard.inspectFileSystemAccess('https://example.com/a/../b');
  assert.strictEqual(r.reason, guard.REASON.PATH_TRAVERSAL);
});

test('编码穿越拒绝', () => {
  const r = guard.inspectFileSystemAccess('https://example.com/a/%2e%2e/b');
  assert.strictEqual(r.reason, guard.REASON.PATH_TRAVERSAL);
});

test('punycode 主机拒绝', () => {
  const r = guard.inspectFileSystemAccess('https://xn--80ak6aa92e.com/app');
  assert.strictEqual(r.reason, guard.REASON.PUNYCODE_HOST);
});

test('裸 IP 主机拒绝', () => {
  const r = guard.inspectFileSystemAccess('https://192.168.1.10/app');
  assert.strictEqual(r.reason, guard.REASON.IP_LITERAL_HOST);
});

test('回环 IP 允许', () => {
  const r = guard.inspectFileSystemAccess('https://127.0.0.1/app');
  assert.strictEqual(r.allowed, true);
});

test('超长地址拒绝', () => {
  const r = guard.inspectFileSystemAccess(`https://example.com/${'a'.repeat(2100)}`);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});

test('apply 包装返回 changed', () => {
  const ok = guard.applyFileSystemAccessGuard('https://example.com');
  assert.strictEqual(ok.changed, false);
  const bad = guard.applyFileSystemAccessGuard('file:///etc/passwd');
  assert.strictEqual(bad.changed, true);
  assert.strictEqual(bad.allowed, false);
});

test('describeReason 覆盖主要状态', () => {
  assert.strictEqual(typeof guard.describeReason(guard.REASON.OK), 'string');
  assert.strictEqual(typeof guard.describeReason('unknown'), 'string');
});
