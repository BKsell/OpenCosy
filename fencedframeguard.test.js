'use strict';

// fencedframeguard.test.js —— fencedframe：URN 校验、http 解析、三方白名单、嵌套、postMessage 通配、config 体积。

const test = require('node:test');
const assert = require('node:assert/strict');
const f = require('./fencedframeguard');
const { FencedFrameGuard, FF_REASON, isUrnUuid, siteOf, defaultFencedFramePolicy } = f;

function ctx(over) {
  return Object.assign({ origin: 'https://pub.example.com', isTopFrame: true }, over || {});
}

test('合法 urn:uuid 围栏放行', () => {
  const g = new FencedFrameGuard();
  const r = g.decideLoad(ctx(), { urn: 'urn:uuid:36f1a9b2-4c7d-4e01-9a2b-7c8d0e1f2a34' });
  assert.equal(r.decision, 'allow');
});

test('URN 大小写前缀与非法 hex 拒绝', () => {
  const g = new FencedFrameGuard();
  assert.equal(g.decideLoad(ctx(), { urn: 'URN:UUID:36f1a9b2-4c7d-4e01-9a2b-7c8d0e1f2a34' }).decision, 'allow');
  assert.equal(g.decideLoad(ctx(), { urn: 'urn:uuid:not-a-uuid' }).reason, FF_REASON.BAD_URN);
  assert.equal(g.decideLoad(ctx(), { urn: 'urn:uuid:36f1a9b2-4c7d-4e01-9a2b-7c8d0e1f2azz' }).reason, FF_REASON.BAD_URN);
});

test('http 解析 URL 默认拒绝', () => {
  const g = new FencedFrameGuard();
  assert.equal(g.decideLoad(ctx(), { resolvedURL: 'http://ads.third.test/a' }).reason, FF_REASON.INSECURE_RESOLVED_URL);
});

test('外部 scheme 解析拒绝', () => {
  const g = new FencedFrameGuard();
  assert.equal(g.decideLoad(ctx(), { resolvedURL: 'intent://x#Intent;end' }).reason, FF_REASON.EXTERNAL_SCHEME);
});

test('三方 https 解析默认拒绝，白名单放行', () => {
  const g = new FencedFrameGuard();
  assert.equal(g.decideLoad(ctx(), { resolvedURL: 'https://ads.partner.com/a' }).reason,
    FF_REASON.THIRD_PARTY_NOT_ALLOWED);
  const pol = defaultFencedFramePolicy();
  pol.allowedEmbedderSites = ['partner.com'];
  const g2 = new FencedFrameGuard(pol);
  assert.equal(g2.decideLoad(ctx(), { resolvedURL: 'https://ads.partner.com/a' }).decision, 'allow');
});

test('嵌套围栏拒绝', () => {
  const g = new FencedFrameGuard();
  const r = g.decideLoad(ctx(), { urn: 'urn:uuid:36f1a9b2-4c7d-4e01-9a2b-7c8d0e1f2a34', nestedInFence: true });
  assert.equal(r.reason, FF_REASON.NESTED_FENCE);
});

test('空 config 拒绝', () => {
  const g = new FencedFrameGuard();
  assert.equal(g.decideLoad(ctx(), null).reason, FF_REASON.NOT_A_FENCE_CONFIG);
  assert.equal(g.decideLoad(ctx(), {}).reason, FF_REASON.NOT_A_FENCE_CONFIG);
});

test('超大序列化 config 拒绝', () => {
  const g = new FencedFrameGuard();
  const r = g.decideLoad(ctx(), { urn: 'urn:uuid:36f1a9b2-4c7d-4e01-9a2b-7c8d0e1f2a34', serialized: 'x'.repeat(20000) });
  assert.equal(r.reason, FF_REASON.CONFIG_TOO_LARGE);
});

test('postMessage 通配 targetOrigin 拒绝，显式放行', () => {
  const g = new FencedFrameGuard();
  assert.equal(g.decidePostMessage({ targetOrigin: '*' }).reason, FF_REASON.POSTMESSAGE_WILDCARD);
  assert.equal(g.decidePostMessage({}).reason, FF_REASON.POSTMESSAGE_WILDCARD);
  assert.equal(g.decidePostMessage({ targetOrigin: 'https://pub.example.com' }).decision, 'allow');
});

test('上下文门禁', () => {
  const g = new FencedFrameGuard();
  const cfg = { urn: 'urn:uuid:36f1a9b2-4c7d-4e01-9a2b-7c8d0e1f2a34' };
  assert.equal(g.decideLoad(ctx({ isTopFrame: false }), cfg).reason, FF_REASON.CROSS_ORIGIN_SUBFRAME);
  assert.equal(g.decideLoad(ctx({ origin: 'http://x' }), cfg).reason, FF_REASON.INSECURE_ORIGIN);
});

test('isUrnUuid/siteOf 纯函数', () => {
  assert.equal(isUrnUuid(123), false);
  assert.equal(isUrnUuid('urn:uuid:00000000-0000-0000-0000-000000000000'), true);
  assert.equal(siteOf('https://pub.example.com:8443/x?y'), 'example.com');
  assert.equal(siteOf('https://a.b.example.com/'), 'example.com');
});
