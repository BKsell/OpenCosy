'use strict';

// wifidirectguard.test.js —— 本地 P2P：STUN/TURN 配置、环回、candidate 私网/环回/链路本地/mDNS/广播。

const test = require('node:test');
const assert = require('node:assert/strict');
const w = require('./wifidirectguard');
const {
  WifiDirectGuard, WD_REASON, parseIpv4, classifyIpv4, stunHost,
  evaluateConfig, extractCandidateAddr, extractCandidateType, defaultWifiDirectPolicy,
} = w;

function ctx(over) {
  return Object.assign({ origin: 'https://app.example.com', isTopFrame: true }, over || {});
}

test('parseIpv4 合法/非法', () => {
  assert.equal(parseIpv4('192.168.1.1'), (((192 * 256 + 168) * 256 + 1) * 256) + 1);
  assert.equal(parseIpv4('10.0.0.255'), 10 * 256 * 256 * 256 + 255);
  assert.equal(parseIpv4('256.1.1.1'), null);
  assert.equal(parseIpv4('1.2.3'), null);
  assert.equal(parseIpv4('a.b.c.d'), null);
  assert.equal(parseIpv4(''), null);
});

test('classifyIpv4 分类', () => {
  assert.equal(classifyIpv4(parseIpv4('127.0.0.1')), 'loopback');
  assert.equal(classifyIpv4(parseIpv4('10.1.2.3')), 'private');
  assert.equal(classifyIpv4(parseIpv4('172.16.0.1')), 'private');
  assert.equal(classifyIpv4(parseIpv4('172.32.0.1')), 'public');
  assert.equal(classifyIpv4(parseIpv4('192.168.5.5')), 'private');
  assert.equal(classifyIpv4(parseIpv4('169.254.0.1')), 'linklocal');
  assert.equal(classifyIpv4(parseIpv4('100.64.0.1')), 'cgNAT');
  assert.equal(classifyIpv4(parseIpv4('224.0.0.1')), 'multicast');
  assert.equal(classifyIpv4(parseIpv4('8.8.8.8')), 'public');
});

test('无 ICE 服务器的普通配置在 https 放行', () => {
  const g = new WifiDirectGuard();
  assert.equal(g.decideConfig(ctx(), { iceServers: [] }).decision, 'allow');
});

test('非顶层/非 https 拒绝', () => {
  const g = new WifiDirectGuard();
  assert.equal(g.decideConfig(ctx({ isTopFrame: false }), {}).reason, WD_REASON.CROSS_ORIGIN_SUBFRAME);
  assert.equal(g.decideConfig(ctx({ origin: 'http://x' }), {}).reason, WD_REASON.INSECURE_ORIGIN);
});

test('turn 携带凭据走明文被拒', () => {
  const pol = defaultWifiDirectPolicy();
  const r = evaluateConfig({ iceServers: [{ urls: 'turn:relay.example.com:3478', username: 'u', credential: 'p' }] }, pol);
  assert.equal(r.reason, WD_REASON.NO_STUN_OVER_HTTP);
});

test('环回 STUN 被拒', () => {
  const pol = defaultWifiDirectPolicy();
  const r = evaluateConfig({ iceServers: [{ urls: 'stun:127.0.0.1:3478' }] }, pol);
  assert.equal(r.reason, WD_REASON.STUN_HOST_BLOCKED);
});

test('STUN 主机后缀黑名单', () => {
  const pol = defaultWifiDirectPolicy();
  pol.blockedStunHostSuffixes = ['evil-stun.net'];
  const r = evaluateConfig({ iceServers: [{ urls: 'stun:relay.evil-stun.net:3478' }] }, pol);
  assert.equal(r.reason, WD_REASON.STUN_HOST_BLOCKED);
});

test('host 候选环回地址拒绝', () => {
  const g = new WifiDirectGuard();
  assert.equal(g.decideCandidate({ address: '127.0.0.1' }).reason, WD_REASON.LOOPBACK_CANDIDATE);
});

test('私网候选默认放行，开启硬策略后拒绝', () => {
  const g = new WifiDirectGuard();
  assert.equal(g.decideCandidate({ address: '192.168.0.5' }).decision, 'allow');
  const pol = defaultWifiDirectPolicy();
  pol.blockLocalPrivateCandidates = true;
  const g2 = new WifiDirectGuard(pol);
  assert.equal(g2.decideCandidate({ address: '10.0.0.7' }).reason, WD_REASON.LOCAL_CANDIDATE_PRIVATE);
});

test('链路本地/组播候选拒绝', () => {
  const g = new WifiDirectGuard();
  assert.equal(g.decideCandidate({ address: '169.254.1.1' }).reason, WD_REASON.BAD_BIND_ADDRESS);
  assert.equal(g.decideCandidate({ address: '224.0.0.251' }).reason, WD_REASON.BAD_BIND_ADDRESS);
});

test('mDNS .local 候选默认拒绝', () => {
  const g = new WifiDirectGuard();
  const r = g.decideCandidate({ address: 'a1b2c3d4-5678-90ef.local' });
  assert.equal(r.reason, WD_REASON.MDNS_HOSTNAME_LEAK);
});

test('candidate 字符串解析地址与类型', () => {
  const c = 'candidate:842163049 1 udp 1677729535 203.0.113.5 54321 typ srflx';
  assert.equal(extractCandidateAddr(c), '203.0.113.5');
  assert.equal(extractCandidateType(c), 'srflx');
  const g = new WifiDirectGuard();
  assert.equal(g.decideCandidate(c, 'srflx').decision, 'allow');
});

test('超长 candidate 字符串拒绝', () => {
  const g = new WifiDirectGuard();
  const c = 'candidate:' + 'x'.repeat(1100);
  assert.equal(g.decideCandidate(c).reason, WD_REASON.CANDIDATE_TOO_LONG);
});

test('非法 candidate 拒绝', () => {
  const g = new WifiDirectGuard();
  assert.equal(g.decideCandidate(null).reason, WD_REASON.BAD_CANDIDATE);
  assert.equal(g.decideCandidate('candidate: no address here').reason, WD_REASON.BAD_CANDIDATE);
});

test('stunHost 纯字符解析', () => {
  assert.equal(stunHost('stun:stun.example.com:3478').host, 'stun.example.com');
  assert.equal(stunHost('stuns://stun.example.com/').scheme, 'stuns');
});
