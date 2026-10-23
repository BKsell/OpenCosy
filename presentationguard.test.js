'use strict';

// presentationguard.test.js —— Presentation：手势、URL 数量/scheme/私网、reconnect、presentationId。

const test = require('node:test');
const assert = require('node:assert/strict');
const p = require('./presentationguard');
const { PresentationGuard, PG_REASON, defaultPresentationPolicy, isPrivateHost } = p;

function ctx(over) { return Object.assign({ origin: 'https://slide.example.com', userGesture: true }, over || {}); }

test('合规投屏放行', () => {
  const g = new PresentationGuard();
  assert.equal(g.decideStart(ctx(), 'start', ['https://slide.example.com/deck']).decision, 'allow');
});

test('无手势/非 https 拒绝', () => {
  const g = new PresentationGuard();
  assert.equal(g.decideStart(ctx({ userGesture: false }), 'start', ['https://x/']).reason, PG_REASON.NO_GESTURE);
  assert.equal(g.decideStart(ctx({ origin: 'http://x' }), 'start', ['https://x/']).reason, PG_REASON.INSECURE_ORIGIN);
});

test('无 URL / URL 过多拒绝', () => {
  const g = new PresentationGuard();
  assert.equal(g.decideStart(ctx(), 'start', []).reason, PG_REASON.NO_URLS);
  const many = [];
  for (let i = 0; i < 5; i++) many.push('https://x/' + i);
  assert.equal(g.decideStart(ctx(), 'start', many).reason, PG_REASON.TOO_MANY_URLS);
});

test('http/cast scheme 拒绝', () => {
  const g = new PresentationGuard();
  assert.equal(g.decideStart(ctx(), 'start', ['http://slide.example.com/']).reason, PG_REASON.BAD_URL_SCHEME);
  assert.equal(g.decideStart(ctx(), 'start', ['cast://device/']).reason, PG_REASON.BAD_URL_SCHEME);
});

test('私网/环回/组播目标拒绝', () => {
  const g = new PresentationGuard();
  assert.equal(g.decideStart(ctx(), 'start', ['https://192.168.1.20/deck']).reason, PG_REASON.TARGET_PRIVATE);
  assert.equal(g.decideStart(ctx(), 'start', ['https://239.255.0.1/']).reason, PG_REASON.TARGET_PRIVATE);
});

test('reconnect 默认拒绝，放开后校验 id', () => {
  const g = new PresentationGuard();
  assert.equal(g.decideStart(ctx(), 'reconnect', null, 'abc').reason, PG_REASON.RECONNECT_DISABLED);
  const pol = defaultPresentationPolicy();
  pol.allowReconnect = true;
  const g2 = new PresentationGuard(pol);
  assert.equal(g2.decideStart(ctx(), 'reconnect', null, '').reason, PG_REASON.BAD_PRESENTATION_ID);
  assert.equal(g2.decideStart(ctx(), 'reconnect', null, 'pid-1').decision, 'allow');
});

test('isPrivateHost 判定', () => {
  assert.equal(isPrivateHost('224.0.0.251'), true);
  assert.equal(isPrivateHost('8.8.8.8'), false);
});
