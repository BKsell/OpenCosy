'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { analyze } = require('./phishurl_core');

test('全角主机经 NFKC 折叠后命中兼容字符信号', () => {
  const r = analyze('https://ｅｘａｍｐｌｅ.ｃｏｍ/login');
  assert.ok(r);
  assert.ok(r.signals.some(s => s.code === 'compatFoldedHost'));
  assert.strictEqual(r.hostname, 'example.com');
});

test('全角品牌主机折叠后才暴露品牌词', () => {
  const r = analyze('https://ｐａｙｐａｌ.ｃｏｍ/verify');
  assert.ok(r);
  assert.strictEqual(r.brand, 'paypal');
  assert.ok(r.signals.some(s => s.code === 'compatFoldedHost'));
});

test('纯 ASCII 主机不触发兼容字符信号', () => {
  const r = analyze('https://paypal.com.secure-login.xyz:8443/');
  assert.ok(r);
  assert.ok(!r.signals.some(s => s.code === 'compatFoldedHost'));
});

test('无风险地址仍返回 null', () => {
  assert.strictEqual(analyze('https://example.com/a'), null);
});
