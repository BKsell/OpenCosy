'use strict';

// attributionguard.test.js —— 归因报告：上下文、端点 https/同站、debug、数量、窗口、epsilon。

const test = require('node:test');
const assert = require('node:assert/strict');
const a = require('./attributionguard');
const { AttributionGuard, AR_REASON, defaultAttributionPolicy } = a;

function ctx(over) {
  return Object.assign({ origin: 'https://ads.example.com', isTopFrame: true }, over || {});
}
function reg(over) {
  return Object.assign({ endpoints: ['https://ads.example.com/report'] }, over || {});
}

test('合规 source 注册放行', () => {
  const g = new AttributionGuard();
  const r = g.decideRegister(ctx(), 'source', reg({ eventReports: 1, aggregatableReports: 10, epsilon: 10 }));
  assert.equal(r.decision, 'allow');
});

test('trigger 注册放行', () => {
  const g = new AttributionGuard();
  assert.equal(g.decideRegister(ctx(), 'trigger', reg()).decision, 'allow');
});

test('非顶层默认拒绝', () => {
  const g = new AttributionGuard();
  assert.equal(g.decideRegister(ctx({ isTopFrame: false }), 'source', reg()).reason, AR_REASON.THIRD_PARTY_CONTEXT);
});

test('非 https 页面拒绝', () => {
  const g = new AttributionGuard();
  assert.equal(g.decideRegister(ctx({ origin: 'http://x' }), 'source', reg()).reason, AR_REASON.INSECURE_ORIGIN);
});

test('http 报告端点拒绝', () => {
  const g = new AttributionGuard();
  assert.equal(g.decideRegister(ctx(), 'source', reg({ endpoints: ['http://ads.example.com/r'] })).reason,
    AR_REASON.INSECURE_REPORT_ENDPOINT);
});

test('外部 scheme 端点拒绝', () => {
  const g = new AttributionGuard();
  assert.equal(g.decideRegister(ctx(), 'source', reg({ endpoints: ['data:text/plain,x'] })).reason,
    AR_REASON.BAD_ENDPOINT);
});

test('跨站报告端点默认拒绝，白名单放行', () => {
  const g = new AttributionGuard();
  assert.equal(g.decideRegister(ctx(), 'source', reg({ endpoints: ['https://collector.other.com/r'] })).reason,
    AR_REASON.ENDPOINT_CROSS_SITE);
  const pol = defaultAttributionPolicy();
  pol.allowedReporterSites = ['other.com'];
  const g2 = new AttributionGuard(pol);
  assert.equal(g2.decideRegister(ctx(), 'source', reg({ endpoints: ['https://collector.other.com/r'] })).decision, 'allow');
});

test('无端点拒绝', () => {
  const g = new AttributionGuard();
  assert.equal(g.decideRegister(ctx(), 'source', { endpoints: [] }).reason, AR_REASON.BAD_ENDPOINT);
});

test('debug 报告默认拒绝', () => {
  const g = new AttributionGuard();
  assert.equal(g.decideRegister(ctx(), 'source', reg({ debugReporting: true })).reason, AR_REASON.DEBUG_REPORTING);
});

test('事件级报告过多拒绝', () => {
  const g = new AttributionGuard();
  assert.equal(g.decideRegister(ctx(), 'source', reg({ eventReports: 3 })).reason, AR_REASON.EVENT_REPORT_TOO_MANY);
});

test('聚合报告过多拒绝', () => {
  const g = new AttributionGuard();
  assert.equal(g.decideRegister(ctx(), 'source', reg({ aggregatableReports: 50 })).reason,
    AR_REASON.EVENT_REPORT_TOO_MANY);
});

test('窗口超限/非法拒绝', () => {
  const g = new AttributionGuard();
  assert.equal(g.decideRegister(ctx(), 'source', reg({ eventWindowSeconds: 90 * 24 * 3600 })).reason,
    AR_REASON.WINDOW_TOO_LARGE);
  assert.equal(g.decideRegister(ctx(), 'source', reg({ eventWindowSeconds: -1 })).reason,
    AR_REASON.WINDOW_TOO_LARGE);
});

test('epsilon 过大/非法拒绝', () => {
  const g = new AttributionGuard();
  assert.equal(g.decideRegister(ctx(), 'source', reg({ epsilon: 20 })).reason, AR_REASON.EPSILON_TOO_LARGE);
  assert.equal(g.decideRegister(ctx(), 'source', reg({ epsilon: -1 })).reason, AR_REASON.PRIVACY_BUDGET_INVALID);
});

test('非法 kind 拒绝', () => {
  const g = new AttributionGuard();
  assert.equal(g.decideRegister(ctx(), 'bogus', reg()).reason, AR_REASON.BAD_CONTEXT);
});
