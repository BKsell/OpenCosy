'use strict';

// browsingtopicsguard.test.js —— Topics：三方、敏感主题过滤/整拒、数量、频率、observe 投毒。

const test = require('node:test');
const assert = require('node:assert/strict');
const t = require('./browsingtopicsguard');
const { BrowsingTopicsGuard, BT_REASON, isSensitiveTopic, defaultTopicsPolicy, BT_FILTER } = t;

function ctx(over) {
  return Object.assign({ origin: 'https://pub.example.com', isTopFrame: true, pageKey: 'p1' }, over || {});
}

test('顶层常规主题放行', () => {
  const g = new BrowsingTopicsGuard();
  const r = g.decide(ctx(), { topics: [1, 2, 3] });
  assert.equal(r.decision, 'allow');
  assert.deepEqual(r.topics, [1, 2, 3]);
});

test('三方上下文默认拒绝，白名单放行', () => {
  const g = new BrowsingTopicsGuard();
  assert.equal(g.decide(ctx({ isTopFrame: false }), { topics: [1] }).reason, BT_REASON.THIRD_PARTY_CONTEXT);
  const pol = defaultTopicsPolicy();
  pol.allowedCallerSites = ['partner.net'];
  const g2 = new BrowsingTopicsGuard(pol);
  assert.equal(g2.decide(ctx({ isTopFrame: false, origin: 'https://p.partner.net' }), { topics: [1] }).decision, 'allow');
});

test('敏感主题默认被过滤', () => {
  const g = new BrowsingTopicsGuard();
  const r = g.decide(ctx(), { topics: [1, 182, 3] }); // 182=癌症
  assert.equal(r.decision, BT_FILTER);
  assert.deepEqual(r.topics, [1, 3]);
  assert.deepEqual(r.filtered, [182]);
});

test('整单拒绝策略下含敏感主题拒绝', () => {
  const pol = defaultTopicsPolicy();
  pol.blockIfAnySensitive = true;
  const g = new BrowsingTopicsGuard(pol);
  assert.equal(g.decide(ctx(), { topics: [236] }).reason, BT_REASON.SENSITIVE_TOPIC_PRESENT);
});

test('主题数量过多拒绝', () => {
  const g = new BrowsingTopicsGuard();
  assert.equal(g.decide(ctx(), { topics: [1, 2, 3, 4] }).reason, BT_REASON.TOO_MANY_TOPICS);
});

test('每页调用频率上限', () => {
  const g = new BrowsingTopicsGuard();
  g.decide(ctx());
  g.decide(ctx());
  assert.equal(g.decide(ctx()).reason, BT_REASON.RATE_LIMIT);
  g.resetPage('p1');
  assert.equal(g.decide(ctx()).decision, 'allow');
});

test('三方 observe 画像投毒拒绝', () => {
  const pol = defaultTopicsPolicy();
  pol.allowedCallerSites = ['partner.net'];
  const g = new BrowsingTopicsGuard(pol);
  assert.equal(g.decide(ctx({ isTopFrame: false, origin: 'https://a.partner.net' }),
    { topics: [1], observe: true }).reason, BT_REASON.OBSERVE_MANIPULATION);
});

test('API 关闭/非 https 拒绝', () => {
  const pol = defaultTopicsPolicy();
  pol.apiEnabled = false;
  const g = new BrowsingTopicsGuard(pol);
  assert.equal(g.decide(ctx(), { topics: [1] }).reason, BT_REASON.API_DISABLED);
  const g2 = new BrowsingTopicsGuard();
  assert.equal(g2.decide(ctx({ origin: 'http://x' }), { topics: [1] }).reason, BT_REASON.INSECURE_ORIGIN);
});

test('isSensitiveTopic 区间判定', () => {
  assert.equal(isSensitiveTopic(182), true);
  assert.equal(isSensitiveTopic(236), true);
  assert.equal(isSensitiveTopic(237), true);
  assert.equal(isSensitiveTopic(1), false);
  assert.equal(isSensitiveTopic('x'), false);
  assert.equal(isSensitiveTopic(182.5), false);
});
