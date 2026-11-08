'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./altsvcguard');

const PAGE = { url: 'https://example.com/a' };

test('无 Alt-Svc 返回 missing', () => {
  const r = guard.applyAltSvcGuard({}, PAGE);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('同源 h3 保留', () => {
  const headers = { 'alt-svc': ['h3=":443"; ma=86400'] };
  const r = guard.applyAltSvcGuard(headers, PAGE);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.strictEqual(r.verdict[0].protocol, 'h3');
});

test('显式同主机同端口保留', () => {
  const headers = { 'alt-svc': ['h3="example.com:443"'] };
  const r = guard.applyAltSvcGuard(headers, PAGE);
  assert.strictEqual(r.changed, false);
});

test('跨源主机整体剥离', () => {
  const headers = { 'alt-svc': ['h3="cdn.evil.example:443"'] };
  const r = guard.applyAltSvcGuard(headers, PAGE);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.CROSS_ORIGIN);
  assert.strictEqual(headers['alt-svc'], undefined);
});

test('混合条目中任一跨源即整体剥离', () => {
  const headers = { 'alt-svc': ['h3=":443", h2="elsewhere.example:80"'] };
  const r = guard.applyAltSvcGuard(headers, PAGE);
  assert.strictEqual(r.reason, guard.REASON.CROSS_ORIGIN);
});

test('clear 指令被剥离', () => {
  const headers = { 'alt-svc': ['clear'] };
  const r = guard.applyAltSvcGuard(headers, PAGE);
  assert.strictEqual(r.reason, guard.REASON.CLEAR_DIRECTIVE);
  assert.strictEqual(headers['alt-svc'], undefined);
});

test('缺少引号视为非法', () => {
  const headers = { 'alt-svc': ['h3=:443'] };
  const r = guard.applyAltSvcGuard(headers, PAGE);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('端口为 0 视为非法', () => {
  const headers = { 'alt-svc': ['h3=":0"'] };
  const r = guard.applyAltSvcGuard(headers, PAGE);
  assert.strictEqual(r.reason, guard.REASON.BAD_PORT);
});

test('端口非数字视为非法', () => {
  const headers = { 'alt-svc': ['h3="example.com:abc"'] };
  const r = guard.applyAltSvcGuard(headers, PAGE);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('条目过多整体剥离', () => {
  const items = [];
  for (let i = 0; i < 9; i += 1) items.push(`h3=":443"`);
  const headers = { 'alt-svc': [items.join(', ')] };
  const r = guard.applyAltSvcGuard(headers, PAGE);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
});

test('超长值整体剥离', () => {
  const headers = { 'alt-svc': ['h3="' + 'a'.repeat(600) + '"'] };
  const r = guard.applyAltSvcGuard(headers, PAGE);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('IPv6 同源保留', () => {
  const headers = { 'alt-svc': ['h3="[::1]:443"'] };
  const r = guard.applyAltSvcGuard(headers, { url: 'https://[::1]/a' });
  assert.strictEqual(r.changed, false);
});

test('IPv6 跨源剥离', () => {
  const headers = { 'alt-svc': ['h3="[2001:db8::1]:443"'] };
  const r = guard.applyAltSvcGuard(headers, PAGE);
  assert.strictEqual(r.reason, guard.REASON.CROSS_ORIGIN);
});

test('大小写键名被识别', () => {
  const headers = { 'Alt-Svc': ['h3=":443"'] };
  const r = guard.applyAltSvcGuard(headers, PAGE);
  assert.strictEqual(r.changed, false);
});

test('describeReason 覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
