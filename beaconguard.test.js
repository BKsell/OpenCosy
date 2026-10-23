'use strict';

// beaconguard.test.js —— sendBeacon/keepalive 出向信标：scheme、第三方、黑名单、体积、卸载洪水、跨源去查询。

const test = require('node:test');
const assert = require('node:assert/strict');
const bc = require('./beaconguard');
const { BeaconGuard, BC_REASON, BC_STRIP, targetSchemeHost, byteLen, defaultBeaconPolicy } = bc;

function ctx(over) {
  return Object.assign({ origin: 'https://app.example.com', blocked: false, isUnloading: false }, over || {});
}

test('目标 URL 解析', () => {
  const t = targetSchemeHost('https://collector.third.com/track?uid=1#frag');
  assert.equal(t.scheme, 'https');
  assert.equal(t.host, 'collector.third.com');
});

test('非 https 目标默认拒绝', () => {
  const g = new BeaconGuard();
  assert.equal(g.decideBeacon(ctx(), 'http://collector.third.com/ping', 'x').reason, BC_REASON.INSECURE_TARGET);
});

test('非法 scheme 拒绝', () => {
  const g = new BeaconGuard();
  assert.equal(g.decideBeacon(ctx(), 'data:text/plain,x', 'x').reason, BC_REASON.BAD_SCHEME);
});

test('第三方信标默认拒绝', () => {
  const g = new BeaconGuard();
  assert.equal(g.decideBeacon(ctx(), 'https://tracker.other.com/p', 'x').reason, BC_REASON.THIRD_PARTY_NOT_ALLOWED);
});

test('第三方白名单放行但跨源去查询串', () => {
  const pol = defaultBeaconPolicy();
  pol.allowedHosts = ['metrics.partner.com'];
  const g = new BeaconGuard(pol);
  const r = g.decideBeacon(ctx(), 'https://metrics.partner.com/p?secret=1', 'x');
  assert.equal(r.decision, BC_STRIP);
  assert.ok(r.safeUrl.indexOf('secret') < 0);
});

test('同源信标直接放行', () => {
  const g = new BeaconGuard();
  assert.equal(g.decideBeacon(ctx(), 'https://app.example.com/ingest', 'data').decision, 'allow');
});

test('主机黑名单后缀拦截子域', () => {
  const pol = defaultBeaconPolicy();
  pol.allowThirdParty = true;
  pol.blockedHostSuffixes = ['evil-track.net'];
  const g = new BeaconGuard(pol);
  assert.equal(g.decideBeacon(ctx(), 'https://a.evil-track.net/x', 'x').reason, BC_REASON.HOST_BLOCKED);
});

test('超大载荷拒绝', () => {
  const g = new BeaconGuard();
  const big = 'x'.repeat(64 * 1024 + 1);
  assert.equal(g.decideBeacon(ctx(), 'https://app.example.com/x', big).reason, BC_REASON.PAYLOAD_TOO_LARGE);
});

test('卸载阶段信标洪水限制', () => {
  const g = new BeaconGuard();
  const c = Object.assign(ctx(), { isUnloading: true });
  assert.equal(g.decideBeacon(c, 'https://app.example.com/a', '1').decision, 'allow');
  assert.equal(g.decideBeacon(c, 'https://app.example.com/b', '2').decision, 'allow');
  assert.equal(g.decideBeacon(c, 'https://app.example.com/c', '3').reason, BC_REASON.UNLOAD_FLOOD);
});

test('字节长度统计多字节', () => {
  assert.equal(byteLen('a'), 1);
  assert.ok(byteLen('中') === 3);
});
