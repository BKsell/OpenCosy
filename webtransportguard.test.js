'use strict';

// webtransportguard.test.js —— WebTransport：scheme、私网/元数据、端口、证书哈希、datagram 速率与大小。

const test = require('node:test');
const assert = require('node:assert/strict');
const w = require('./webtransportguard');
const { WebTransportGuard, WT_REASON, hostPortOf, isPrivateOrSpecial, defaultWebTransportPolicy } = w;

let now = 1_700_000_000_000;
function clock() { return now; }
function ctx(over) { return Object.assign({ origin: 'https://app.example.com' }, over || {}); }

test('合规 https 公网连接放行', () => {
  const g = new WebTransportGuard(undefined, clock);
  const r = g.decideConnect(ctx(), 'https://edge.example.com:443/echo');
  assert.equal(r.decision, 'allow');
  assert.equal(r.host, 'edge.example.com');
  assert.equal(r.port, 443);
});

test('非 https scheme 拒绝', () => {
  const g = new WebTransportGuard(undefined, clock);
  assert.equal(g.decideConnect(ctx(), 'http://edge.example.com/').reason, WT_REASON.BAD_URL_SCHEME);
  assert.equal(g.decideConnect(ctx(), 'quic-transport://x/').reason, WT_REASON.BAD_URL_SCHEME);
});

test('私网/环回/元数据地址拒绝', () => {
  const g = new WebTransportGuard(undefined, clock);
  assert.equal(g.decideConnect(ctx(), 'https://192.168.0.5/').reason, WT_REASON.TARGET_PRIVATE_ADDRESS);
  assert.equal(g.decideConnect(ctx(), 'https://169.254.169.254/').reason, WT_REASON.TARGET_PRIVATE_ADDRESS);
  assert.equal(g.decideConnect(ctx(), 'https://localhost/').reason, WT_REASON.TARGET_PRIVATE_ADDRESS);
});

test('敏感端口拒绝', () => {
  const g = new WebTransportGuard(undefined, clock);
  assert.equal(g.decideConnect(ctx(), 'https://db.example.com:6379/').reason, WT_REASON.PORT_BLOCKED);
  assert.equal(g.decideConnect(ctx(), 'https://h.example.com:3389/').reason, WT_REASON.PORT_BLOCKED);
});

test('serverCertificateHashes 默认拒绝', () => {
  const g = new WebTransportGuard(undefined, clock);
  assert.equal(g.decideConnect(ctx(), 'https://edge.example.com/', {
    serverCertificateHashes: [{ algorithm: 'sha-256', value: 'a'.repeat(64) }],
  }).reason, WT_REASON.BAD_CERT_HASH);
});

test('放开后非法/过期哈希拒绝', () => {
  const pol = defaultWebTransportPolicy();
  pol.allowServerCertificateHashes = true;
  const g = new WebTransportGuard(pol, clock);
  const base = 'https://edge.example.com/';
  assert.equal(g.decideConnect(ctx(), base, {
    serverCertificateHashes: [{ algorithm: 'sha-256', value: 'zz' }],
  }).reason, WT_REASON.BAD_CERT_HASH);
  assert.equal(g.decideConnect(ctx(), base, {
    serverCertificateHashes: [{ algorithm: 'sha-256', value: 'a'.repeat(64), validityExpiry: 100 }],
  }).reason, WT_REASON.CERT_HASH_EXPIRED);
  assert.equal(g.decideConnect(ctx(), base, {
    serverCertificateHashes: [{ algorithm: 'sha-256', value: 'a'.repeat(64), validityExpiry: 9_999_999_999 }],
  }).decision, 'allow');
});

test('datagram 过大拒绝', () => {
  const g = new WebTransportGuard(undefined, clock);
  assert.equal(g.decideDatagram(ctx(), 2000).reason, WT_REASON.DATAGRAM_TOO_LARGE);
});

test('datagram 速率上限', () => {
  const pol = defaultWebTransportPolicy();
  pol.maxDatagramsPerSecond = 3;
  const g = new WebTransportGuard(pol, clock);
  for (let i = 0; i < 3; i++) assert.equal(g.decideDatagram(ctx(), 100).decision, 'allow');
  assert.equal(g.decideDatagram(ctx(), 100).reason, WT_REASON.DATAGRAM_RATE_TOO_HIGH);
  now += 1100;
  assert.equal(g.decideDatagram(ctx(), 100).decision, 'allow');
});

test('hostPortOf/isPrivateOrSpecial 纯字符', () => {
  assert.deepEqual(hostPortOf('https://[::1]:443/').host, '::1');
  assert.equal(isPrivateOrSpecial('100.100.100.200'), true);
  assert.equal(isPrivateOrSpecial('8.8.8.8'), false);
});
