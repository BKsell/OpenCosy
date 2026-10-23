'use strict';

// speculativefetchguard.test.js —— 推测规则：prerender 开关、eager、目标 https/私网、匿名化、referrerPolicy、数量。

const test = require('node:test');
const assert = require('node:assert/strict');
const s = require('./speculativefetchguard');
const { SpeculativeFetchGuard, SF_REASON, isPrivateHost, defaultSpeculativePolicy } = s;

function ctx(over) {
  return Object.assign({ origin: 'https://news.example.com' }, over || {});
}

test('同站 https prefetch 放行', () => {
  const g = new SpeculativeFetchGuard();
  const r = g.decideRule(ctx(), { action: 'prefetch', urls: ['https://news.example.com/a'] });
  assert.equal(r.decision, 'allow');
});

test('prerender 默认拒绝', () => {
  const g = new SpeculativeFetchGuard();
  assert.equal(g.decideRule(ctx(), { action: 'prerender', urls: ['https://news.example.com/a'] }).reason,
    SF_REASON.PRERENDER_DISABLED);
});

test('未知 action/坏 rule 拒绝', () => {
  const g = new SpeculativeFetchGuard();
  assert.equal(g.decideRule(ctx(), { action: 'bogus' }).reason, SF_REASON.UNKNOWN_ACTION);
  assert.equal(g.decideRule(ctx(), null).reason, SF_REASON.BAD_RULE);
});

test('eager 默认拒绝', () => {
  const g = new SpeculativeFetchGuard();
  assert.equal(g.decideRule(ctx(), { action: 'prefetch', eagerness: 'eager', urls: ['https://news.example.com/a'] }).reason,
    SF_REASON.EAGER_DISABLED);
});

test('http 目标拒绝', () => {
  const g = new SpeculativeFetchGuard();
  assert.equal(g.decideRule(ctx(), { action: 'prefetch', urls: ['http://news.example.com/a'] }).reason,
    SF_REASON.INSECURE_TARGET);
});

test('内网目标拒绝（SSRF 面）', () => {
  const g = new SpeculativeFetchGuard();
  assert.equal(g.decideRule(ctx(), { action: 'prefetch', urls: ['https://192.168.1.1/admin'] }).reason,
    SF_REASON.TARGET_PRIVATE_ADDRESS);
  assert.equal(g.decideRule(ctx(), { action: 'prefetch', urls: ['http://localhost:8080/'] }).reason,
    SF_REASON.INSECURE_TARGET);
});

test('跨站 prefetch 要求匿名化与 referrerPolicy', () => {
  const g = new SpeculativeFetchGuard();
  const base = { action: 'prefetch', urls: ['https://cdn.other.com/x'] };
  assert.equal(g.decideRule(ctx(), base).reason, SF_REASON.ANONYMIZATION_REQUIRED);
  const withAnon = Object.assign({}, base, { requires: ['anonymous-client-ip'] });
  assert.equal(g.decideRule(ctx(), withAnon).reason, SF_REASON.PREFETCH_WITHOUT_REFERRER_POLICY);
  const ok = Object.assign({}, withAnon, { referrerPolicy: 'no-referrer' });
  assert.equal(g.decideRule(ctx(), ok).decision, 'allow');
});

test('目标数量过多拒绝', () => {
  const g = new SpeculativeFetchGuard();
  const urls = [];
  for (let i = 0; i < 12; i++) urls.push('https://news.example.com/p' + i);
  assert.equal(g.decideRule(ctx(), { action: 'prefetch', urls }).reason, SF_REASON.TARGET_TOO_MANY);
});

test('非 https 页面拒绝', () => {
  const g = new SpeculativeFetchGuard();
  assert.equal(g.decideRule({ origin: 'http://x' }, { action: 'prefetch', urls: ['https://x/'] }).reason,
    SF_REASON.INSECURE_ORIGIN);
});

test('isPrivateHost 判定', () => {
  assert.equal(isPrivateHost('localhost'), true);
  assert.equal(isPrivateHost('a.localhost'), true);
  assert.equal(isPrivateHost('10.0.0.1'), true);
  assert.equal(isPrivateHost('172.16.5.5'), true);
  assert.equal(isPrivateHost('169.254.1.1'), true);
  assert.equal(isPrivateHost('8.8.8.8'), false);
  assert.equal(isPrivateHost('example.com'), false);
});
