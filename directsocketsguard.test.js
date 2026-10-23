'use strict';

// directsocketsguard.test.js —— Direct Sockets：手势、TCP/UDP/监听、私网、端口、混淆 IP、socket 上限。

const test = require('node:test');
const assert = require('node:assert/strict');
const d = require('./directsocketsguard');
const { DirectSocketsGuard, DS_REASON, defaultDirectSocketsPolicy, normalizeIpv4, classifyIpv4 } = d;

function ctx(over) {
  return Object.assign({ origin: 'https://term.example.com', userGesture: true }, over || {});
}

test('公网 TCP 高端口放行', () => {
  const g = new DirectSocketsGuard();
  assert.equal(g.decideConnect(ctx(), 'tcp', '203.0.113.9', 8443).decision, 'allow');
});

test('无手势/非 https 拒绝', () => {
  const g = new DirectSocketsGuard();
  assert.equal(g.decideConnect(ctx({ userGesture: false }), 'tcp', '203.0.113.9', 8443).reason, DS_REASON.NO_GESTURE);
  assert.equal(g.decideConnect(ctx({ origin: 'http://x' }), 'tcp', '203.0.113.9', 8443).reason, DS_REASON.INSECURE_ORIGIN);
});

test('UDP 默认禁用', () => {
  const g = new DirectSocketsGuard();
  assert.equal(g.decideConnect(ctx(), 'udp', '203.0.113.9', 5000).reason, DS_REASON.UDP_DISABLED);
});

test('监听套接字默认禁用', () => {
  const g = new DirectSocketsGuard();
  assert.equal(g.decideListen(ctx(), 9000).reason, DS_REASON.SERVER_SOCKET_DISABLED);
});

test('私网/环回/链路本地目标拒绝', () => {
  const g = new DirectSocketsGuard();
  assert.equal(g.decideConnect(ctx(), 'tcp', '10.0.0.5', 8443).reason, DS_REASON.PRIVATE_TARGET);
  assert.equal(g.decideConnect(ctx(), 'tcp', '127.0.0.1', 8443).reason, DS_REASON.PRIVATE_TARGET);
  assert.equal(g.decideConnect(ctx(), 'tcp', '169.254.1.1', 8443).reason, DS_REASON.PRIVATE_TARGET);
  assert.equal(g.decideConnect(ctx(), 'tcp', 'localhost', 8443).reason, DS_REASON.PRIVATE_TARGET);
  assert.equal(g.decideConnect(ctx(), 'tcp', 'printer.local', 8443).reason, DS_REASON.PRIVATE_TARGET);
});

test('敏感端口拒绝', () => {
  const g = new DirectSocketsGuard();
  assert.equal(g.decideConnect(ctx(), 'tcp', '203.0.113.9', 6379).reason, DS_REASON.PORT_BLOCKED);
  assert.equal(g.decideConnect(ctx(), 'tcp', '203.0.113.9', 22).reason, DS_REASON.PORT_BLOCKED);
});

test('非法端口拒绝', () => {
  const g = new DirectSocketsGuard();
  assert.equal(g.decideConnect(ctx(), 'tcp', '203.0.113.9', 70000).reason, DS_REASON.BAD_PORT);
  assert.equal(g.decideConnect(ctx(), 'tcp', '203.0.113.9', -1).reason, DS_REASON.BAD_PORT);
});

test('socket 数量上限与释放', () => {
  const pol = defaultDirectSocketsPolicy();
  pol.maxSocketsPerOrigin = 2;
  const g = new DirectSocketsGuard(pol);
  assert.equal(g.decideConnect(ctx(), 'tcp', '203.0.113.9', 8443).decision, 'allow');
  assert.equal(g.decideConnect(ctx(), 'tcp', '203.0.113.10', 8443).decision, 'allow');
  assert.equal(g.decideConnect(ctx(), 'tcp', '203.0.113.11', 8443).reason, DS_REASON.TOO_MANY_SOCKETS);
  g.release(ctx());
  assert.equal(g.decideConnect(ctx(), 'tcp', '203.0.113.11', 8443).decision, 'allow');
});

test('八进制/十六进制混淆 IP 仍识别私网', () => {
  const g = new DirectSocketsGuard();
  // 0177.0.0.1 = 127.0.0.1（八进制）
  assert.equal(g.decideConnect(ctx(), 'tcp', '0177.0.0.1', 8443).reason, DS_REASON.PRIVATE_TARGET);
  // 0x7f000001 = 127.0.0.1
  assert.equal(g.decideConnect(ctx(), 'tcp', '0x7f000001', 8443).reason, DS_REASON.PRIVATE_TARGET);
});

test('非法地址字符串拒绝', () => {
  const g = new DirectSocketsGuard();
  assert.equal(g.decideConnect(ctx(), 'tcp', '', 8443).reason, DS_REASON.BAD_ADDRESS);
  assert.equal(g.decideConnect(ctx(), 'tcp', '999.1.1.1', 8443).reason, DS_REASON.BAD_ADDRESS);
});

test('normalizeIpv4 / classifyIpv4 纯字符', () => {
  assert.equal(normalizeIpv4('127.0.0.1'), '127.0.0.1');
  assert.equal(normalizeIpv4('0x7f000001'), '127.0.0.1');
  assert.equal(classifyIpv4('10.20.30.40'), 'private');
  assert.equal(classifyIpv4('8.8.8.8'), 'public');
});

test('放开 UDP/监听后生效', () => {
  const pol = defaultDirectSocketsPolicy();
  pol.udpEnabled = true;
  pol.serverSocketEnabled = true;
  const g = new DirectSocketsGuard(pol);
  assert.equal(g.decideConnect(ctx(), 'udp', '203.0.113.9', 6000).decision, 'allow');
  assert.equal(g.decideListen(ctx(), 0).decision, 'allow');
});
