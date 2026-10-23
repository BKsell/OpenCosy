'use strict';

// windownameguard.test.js —— window.name 跨导航清空、大小限制、外部打开强制 noopener、opener 跨源访问。

const test = require('node:test');
const assert = require('node:assert/strict');
const wn = require('./windownameguard');
const { WindowNameGuard, WN_REASON, originOf, sameOrigin } = wn;

test('origin/同源判定', () => {
  assert.equal(originOf('https://a.example.com/x'), 'https://a.example.com');
  assert.ok(sameOrigin('https://a.example.com/1', 'https://a.example.com/2'));
  assert.ok(!sameOrigin('https://a.example.com/1', 'https://b.other.com/2'));
});

test('非字符串 name 拒绝', () => {
  const g = new WindowNameGuard();
  assert.equal(g.decideSetName(123).reason, WN_REASON.NAME_NON_STRING);
});

test('超大 name 拒绝', () => {
  const g = new WindowNameGuard();
  assert.equal(g.decideSetName('x'.repeat(2049)).reason, WN_REASON.NAME_TOO_LARGE);
});

test('正常 name 放行', () => {
  const g = new WindowNameGuard();
  assert.equal(g.decideSetName('state=abc').allowed, true);
});

test('同源导航保留 name', () => {
  const g = new WindowNameGuard();
  const r = g.decideNameOnNavigation('https://a.com/1', 'https://a.com/2', 'token=1');
  assert.equal(r.readable, true);
  assert.equal(r.effectiveName, 'token=1');
});

test('跨源导航清空 name', () => {
  const g = new WindowNameGuard();
  const r = g.decideNameOnNavigation('https://a.com/1', 'https://b.com/2', 'token=1');
  assert.equal(r.readable, false);
  assert.equal(r.effectiveName, '');
  assert.equal(r.reason, WN_REASON.NAME_ON_CROSS_NAVIGATION_CLEARED);
});

test('外部 target=_blank 无 noopener 强制补 noopener', () => {
  const g = new WindowNameGuard();
  const r = g.decideOpen({ sourceUrl: 'https://a.com/blog', targetUrl: 'https://evil.com/', hasNoopener: false });
  assert.equal(r.allowed, true);
  assert.equal(r.forceNoopener, true);
});

test('已带 noopener 不再强制', () => {
  const g = new WindowNameGuard();
  const r = g.decideOpen({ sourceUrl: 'https://a.com/blog', targetUrl: 'https://evil.com/', hasNoopener: true });
  assert.equal(r.forceNoopener, false);
});

test('noreferrer 隐含 noopener', () => {
  const g = new WindowNameGuard();
  const r = g.decideOpen({ sourceUrl: 'https://a.com/blog', targetUrl: 'https://evil.com/', hasNoreferrer: true });
  assert.equal(r.forceNoopener, false);
});

test('同源打开不强制 noopener', () => {
  const g = new WindowNameGuard();
  const r = g.decideOpen({ sourceUrl: 'https://a.com/1', targetUrl: 'https://a.com/2' });
  assert.equal(r.forceNoopener, false);
});

test('跨源 opener 访问默认拒绝，同源放行', () => {
  const g = new WindowNameGuard();
  assert.equal(g.decideOpenerAccess('https://a.com/1', 'https://b.com/2').access, false);
  assert.equal(g.decideOpenerAccess('https://a.com/1', 'https://a.com/3').access, true);
});
