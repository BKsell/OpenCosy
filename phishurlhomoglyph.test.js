'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { analyze } = require('./phishurl_core');

const CYRILLIC_PAYPAL = 'https://раураl.com/login';
const PUNY_PAYPAL = 'https://xn--l-7sba6dbr.com/login';
const MIXED_PAYPAL = 'https://pаypal.com/login';

test('全西里尔主机折叠成拉丁后命中品牌词', () => {
  const r = analyze(CYRILLIC_PAYPAL);
  assert.ok(r);
  assert.strictEqual(r.brand, 'paypal');
  assert.ok(r.signals.some(s => s.code === 'homoglyphBrand'));
  assert.strictEqual(r.level, 'high');
});

test('拉丁与西里尔混排的单个标签同样命中', () => {
  const r = analyze(MIXED_PAYPAL);
  assert.ok(r);
  assert.strictEqual(r.brand, 'paypal');
  assert.ok(r.signals.some(s => s.code === 'homoglyphBrand'));
});

test('Unicode 与 punycode 两种写法结论一致', () => {
  const a = analyze(CYRILLIC_PAYPAL);
  const b = analyze(PUNY_PAYPAL);
  assert.ok(a && b);
  assert.strictEqual(a.hostname, b.hostname);
  assert.strictEqual(a.score, b.score);
  assert.deepStrictEqual(a.signals.map(s => s.code), b.signals.map(s => s.code));
});

test('纯 ASCII 品牌主机不出现同形字信号', () => {
  const r = analyze('https://paypal.com/a');
  assert.ok(!r || !r.signals.some(s => s.code === 'homoglyphBrand'));
  assert.strictEqual(analyze('https://example.com/a'), null);
});
