'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./serverbannerstripguard');

test('无指纹头时不变更', () => {
  const headers = { 'content-type': ['text/html'] };
  const r = guard.applyServerBannerStripGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('技术栈指纹头被清空', () => {
  const headers = { 'X-Powered-By': ['Express'], 'X-AspNet-Version': ['4.0'], 'X-Generator': ['WordPress 6.2'] };
  const r = guard.applyServerBannerStripGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BANNER_LEAK);
  assert.deepStrictEqual(Object.keys(headers), []);
});

test('Server 头保留产品名剥离版本', () => {
  const headers = { server: ['nginx/1.18.0 (Ubuntu)'] };
  const r = guard.applyServerBannerStripGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.SERVER_SANITIZED);
  assert.deepStrictEqual(headers.server, ['nginx']);
});

test('Server 产品名不变时不报告变更', () => {
  const headers = { server: ['nginx'] };
  const r = guard.applyServerBannerStripGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.deepStrictEqual(headers.server, ['nginx']);
});

test('Server 头含控制字符被清空', () => {
  const headers = { server: ['nginx\u0000evil'] };
  const r = guard.applyServerBannerStripGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers.server, undefined);
});

test('超长 Server 头被清空', () => {
  const headers = { server: [`nginx/${'9'.repeat(guard.MAX_SERVER_LENGTH)}`] };
  const r = guard.applyServerBannerStripGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('代理拓扑头被判 proxy-leak', () => {
  const headers = { via: ['1.1 proxy.internal'], 'x-real-ip': ['10.0.0.5'], 'x-served-by': ['cache-01'] };
  const r = guard.applyServerBannerStripGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.PROXY_LEAK);
  assert.deepStrictEqual(Object.keys(headers), []);
});

test('大小写不敏感键名被删除', () => {
  const headers = { 'X-Runtime': ['0.0231'] };
  const r = guard.applyServerBannerStripGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers['X-Runtime'], undefined);
});

test('数组值只取首项判断', () => {
  const headers = { server: ['Caddy', 'internal'] };
  const r = guard.applyServerBannerStripGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.SERVER_SANITIZED);
  assert.deepStrictEqual(headers.server, ['Caddy']);
});

test('describeReason 覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
