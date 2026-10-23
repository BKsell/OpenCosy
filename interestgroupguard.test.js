'use strict';

// interestgroupguard.test.js —— Protected Audience：owner 同站、lifetime、bidding/render URL、signals、数量、auction。

const test = require('node:test');
const assert = require('node:assert/strict');
const ig = require('./interestgroupguard');
const { InterestGroupGuard, IG_REASON, defaultInterestGroupPolicy, regDomain, hostOf } = ig;

function ctx(over) {
  return Object.assign({ origin: 'https://dsp.ads.example.com', isTopFrame: false }, over || {});
}
function group(over) {
  return Object.assign({
    owner: 'https://dsp.ads.example.com',
    name: 'running-shoes',
    lifetimeSeconds: 7 * 24 * 3600,
    biddingLogicURL: 'https://dsp.ads.example.com/bid.js',
    ads: [{ renderURL: 'https://cdn.ads.example.com/ad.html' }],
    userBiddingSignals: '{"seg":"a"}',
  }, over || {});
}

test('合规 join 放行', () => {
  const g = new InterestGroupGuard();
  assert.equal(g.decideJoin(ctx(), group()).decision, 'allow');
});

test('非 https 页面拒绝', () => {
  const g = new InterestGroupGuard();
  assert.equal(g.decideJoin(ctx({ origin: 'http://x' }), group()).reason, IG_REASON.INSECURE_ORIGIN);
});

test('owner 缺失/非法拒绝', () => {
  const g = new InterestGroupGuard();
  assert.equal(g.decideJoin(ctx(), group({ owner: 'notaurl' })).reason, IG_REASON.BAD_OWNER);
  assert.equal(g.decideJoin(ctx(), null).reason, IG_REASON.BAD_OWNER);
});

test('owner 跨站默认拒绝，白名单放行', () => {
  const g = new InterestGroupGuard();
  assert.equal(g.decideJoin(ctx(), group({ owner: 'https://other.net' })).reason, IG_REASON.OWNER_CROSS_SITE);
  const pol = defaultInterestGroupPolicy();
  pol.allowedJoinSites = ['example.com'];
  const g2 = new InterestGroupGuard(pol);
  assert.equal(g2.decideJoin(ctx(), group({ owner: 'https://dsp.ads.example.com' })).decision, 'allow');
});

test('lifetime 非法/超长拒绝', () => {
  const g = new InterestGroupGuard();
  assert.equal(g.decideJoin(ctx(), group({ lifetimeSeconds: 0 })).reason, IG_REASON.BAD_LIFETIME);
  assert.equal(g.decideJoin(ctx(), group({ lifetimeSeconds: 90 * 24 * 3600 })).reason, IG_REASON.LIFETIME_TOO_LONG);
});

test('biddingLogicURL 非 https 拒绝', () => {
  const g = new InterestGroupGuard();
  assert.equal(g.decideJoin(ctx(), group({ biddingLogicURL: 'http://dsp.ads.example.com/bid.js' })).reason,
    IG_REASON.INSECURE_LOGIC_URL);
});

test('biddingLogicURL 跨 owner 拒绝', () => {
  const g = new InterestGroupGuard();
  assert.equal(g.decideJoin(ctx(), group({ biddingLogicURL: 'https://logic.other.com/bid.js' })).reason,
    IG_REASON.LOGIC_CROSS_OWNER);
});

test('renderURL 非 https / 外部 scheme 拒绝', () => {
  const g = new InterestGroupGuard();
  assert.equal(g.decideJoin(ctx(), group({ ads: [{ renderURL: 'http://cdn.ads.example.com/a' }] })).reason,
    IG_REASON.BAD_RENDER_URL);
  assert.equal(g.decideJoin(ctx(), group({ ads: [{ renderURL: 'intent://x#Intent;end' }] })).reason,
    IG_REASON.RENDER_EXTERNAL_SCHEME);
});

test('signals 过大拒绝', () => {
  const g = new InterestGroupGuard();
  assert.equal(g.decideJoin(ctx(), group({ userBiddingSignals: 'x'.repeat(10000) })).reason,
    IG_REASON.SIGNALS_TOO_LARGE);
});

test('每 owner 兴趣组数量上限', () => {
  const pol = defaultInterestGroupPolicy();
  pol.maxGroupsPerOwner = 2;
  const g = new InterestGroupGuard(pol);
  assert.equal(g.decideJoin(ctx(), group({ name: 'a' })).decision, 'allow');
  assert.equal(g.decideJoin(ctx(), group({ name: 'b' })).decision, 'allow');
  assert.equal(g.decideJoin(ctx(), group({ name: 'c' })).reason, IG_REASON.TOO_MANY_GROUPS_PER_OWNER);
});

test('auction seller/decisionLogic 同站 https', () => {
  const g = new InterestGroupGuard();
  assert.equal(g.decideAuction(ctx(), {
    seller: 'https://ssp.example.com',
    decisionLogicURL: 'https://ssp.example.com/score.js',
  }).decision, 'allow');
  assert.equal(g.decideAuction(ctx(), {
    seller: 'https://ssp.example.com',
    decisionLogicURL: 'http://ssp.example.com/score.js',
  }).reason, IG_REASON.INSECURE_LOGIC_URL);
  assert.equal(g.decideAuction(ctx(), {
    seller: 'https://ssp.example.com',
    decisionLogicURL: 'https://else.net/score.js',
  }).reason, IG_REASON.SELLER_LOGIC_CROSS_SITE);
});

test('hostOf/regDomain 纯字符', () => {
  assert.equal(hostOf('https://a.b.example.com:8443/x?y'), 'a.b.example.com');
  assert.equal(regDomain('a.b.example.com'), 'example.com');
});
