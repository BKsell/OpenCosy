'use strict';

// webrtcleakguard.test.js —— IP 解析与私网判定、mDNS、ICE URI、服务器白名单、候选过滤、隔离门。

const test = require('node:test');
const assert = require('node:assert/strict');
const wr = require('./webrtcleakguard');
const {
  WebRtcLeakGuard, WR_REASON, CAND, defaultWebRtcPolicy,
  parseIpv4, isPrivateOrLocalIPv4, ipv6Scope, endsWithMdns, iceUriScheme, hostOfUrl,
} = wr;

const ORIGIN = 'https://call.example.com';
function ctx(over) {
  return Object.assign({ origin: ORIGIN, isSecureContext: true, blocked: false, hasUserGesture: true, now: 0 }, over || {});
}

test('IPv4 解析', () => {
  assert.deepEqual(parseIpv4('192.168.1.1'), [192, 168, 1, 1]);
  assert.equal(parseIpv4('256.1.1.1'), null);
  assert.equal(parseIpv4('a.1.1.1'), null);
  assert.equal(parseIpv4('1.2.3'), null);
});

test('私网/链路本地判定', () => {
  assert.ok(isPrivateOrLocalIPv4(parseIpv4('10.0.0.1')));
  assert.ok(isPrivateOrLocalIPv4(parseIpv4('172.16.5.5')));
  assert.ok(isPrivateOrLocalIPv4(parseIpv4('172.31.0.1')));
  assert.ok(!isPrivateOrLocalIPv4(parseIpv4('172.32.0.1')));
  assert.ok(isPrivateOrLocalIPv4(parseIpv4('169.254.1.1')));
  assert.ok(!isPrivateOrLocalIPv4(parseIpv4('8.8.8.8')));
});

test('IPv6 本地域判定', () => {
  assert.equal(ipv6Scope('::1'), 'loopback');
  assert.equal(ipv6Scope('fe80::1'), 'local');
  assert.equal(ipv6Scope('fd00::1'), 'local');
  assert.equal(ipv6Scope('2606:4700::1'), 'global');
});

test('mDNS 主机名识别', () => {
  assert.ok(endsWithMdns('abc-123.local'));
  assert.ok(!endsWithMdns('192.168.0.1'));
});

test('ICE URI scheme 白名单', () => {
  assert.equal(iceUriScheme('stun:stun.l.google.com:19302'), 'stun');
  assert.equal(iceUriScheme('turns:turn.example.com:443?transport=tcp'), 'turns');
  assert.equal(iceUriScheme('https://evil.com'), '');
  assert.equal(iceUriScheme('data:anything'), '');
});

test('ICE URL 主机提取', () => {
  assert.equal(hostOfUrl('stun:stun.example.com:3478'), 'stun.example.com');
  assert.equal(hostOfUrl('turns://user@turn.example.com:443'), 'turn.example.com');
});

test('默认禁止页面自带 ICE 服务器', () => {
  const g = new WebRtcLeakGuard();
  const r = g.validateIceServers([{ urls: 'stun:attacker.com:3478' }]);
  assert.equal(r.ok, false);
  assert.equal(r.reason, WR_REASON.ICE_SERVER_NOT_ALLOWED);
});

test('白名单主机放行，非白名单拒绝', () => {
  const pol = defaultWebRtcPolicy();
  pol.allowCustomIceServers = true;
  pol.allowedIceServerHosts = ['stun.example.com'];
  const g = new WebRtcLeakGuard(pol);
  assert.equal(g.validateIceServers([{ urls: 'stun:stun.example.com:3478' }]).ok, true);
  assert.equal(g.validateIceServers([{ urls: 'stun:stun.evil.com:3478' }]).ok, false);
});

test('ICE 服务器数量上限', () => {
  const pol = defaultWebRtcPolicy();
  pol.allowCustomIceServers = true;
  const g = new WebRtcLeakGuard(pol);
  const many = [1, 2, 3, 4, 5].map((i) => ({ urls: 'stun:h' + i + '.com' }));
  assert.equal(g.validateIceServers(many).reason, WR_REASON.TOO_MANY_ICE_SERVERS);
});

test('非安全上下文拒绝建连', () => {
  const g = new WebRtcLeakGuard();
  assert.equal(g.decideConnection(ctx({ isSecureContext: false }), {}).reason, WR_REASON.INSECURE_CONTEXT);
});

test('候选过滤：默认隐藏字面 IP，放行 mDNS 与 relay', () => {
  const g = new WebRtcLeakGuard();
  assert.equal(g.filterCandidate({ type: CAND.HOST, address: '192.168.0.5' }).emit, false);
  assert.equal(g.filterCandidate({ type: CAND.HOST, address: 'a1b2c3.local' }).emit, true);
  assert.equal(g.filterCandidate({ type: CAND.SRFLX, address: '8.8.8.8' }).emit, false);
  assert.equal(g.filterCandidate({ type: CAND.RELAY, address: '203.0.113.5' }).emit, true);
});

test('开启 srflx/字面 IP 后放行公网候选', () => {
  const pol = defaultWebRtcPolicy();
  pol.allowSrflx = true;
  pol.allowLiteralHostIp = true;
  const g = new WebRtcLeakGuard(pol);
  assert.equal(g.filterCandidate({ type: CAND.SRFLX, address: '8.8.8.8' }).emit, true);
  assert.equal(g.filterCandidate({ type: CAND.HOST, address: '10.0.0.1' }).emit, true);
});

test('放宽策略需手势且节流', () => {
  const g = new WebRtcLeakGuard();
  assert.equal(g.requestRelaxedPolicy(ctx({ hasUserGesture: false })).reason, WR_REASON.NO_GESTURE_REQUIRED_HINT);
  assert.equal(g.requestRelaxedPolicy(ctx({ now: 0 })).allowed, true);
  assert.equal(g.requestRelaxedPolicy(ctx({ now: 1000 })).reason, WR_REASON.PERMISSION_THROTTLED);
});
