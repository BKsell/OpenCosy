'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const c = require('./thirdpartycookiejar');

test('第一方放行', () => {
  const d = c.decideThirdPartyCookie('https://a.com/', 'https://a.com/api', new Set());
  assert.equal(d.action, 'allow');
});

test('第三方跟踪拦截', () => {
  const d = c.decideThirdPartyCookie('https://a.com/', 'https://tracker.b.com/beacon', new Set());
  assert.equal(d.action, 'block');
});

test('显式授权的第三方放行', () => {
  const allow = new Set(['pay.example']);
  const d = c.decideThirdPartyCookie('https://shop.com/', 'https://pay.example/checkout', allow);
  assert.equal(d.action, 'allow');
});

test('非安全上下文第三方拦截', () => {
  const d = c.decideThirdPartyCookie('https://a.com/', 'http://b.com/x', new Set());
  assert.equal(d.action, 'block');
});

test('非法 URL 拦截', () => {
  const d = c.decideThirdPartyCookie('nope', 'https://b.com/', new Set());
  assert.equal(d.action, 'block');
});

test('分区标记：跨站打分区', () => {
  assert.equal(c.shouldPartitionCookies('https://a.com/', 'https://b.com/x'), true);
  assert.equal(c.shouldPartitionCookies('https://a.com/', 'https://a.com/x'), false);
});

test('siteKey 归一', () => {
  assert.equal(c.siteKey('https://A.com/x?y=1'), 'https://a.com');
});
