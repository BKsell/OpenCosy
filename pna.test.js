'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const pna = require('./pna');
const {
  SPACE_PUBLIC, SPACE_LINK_LOCAL, SPACE_PRIVATE, SPACE_LOOPBACK, SPACE_UNKNOWN,
} = pna;

// ===== IPv4 =====

test('parseIPv4 正常解析与非法拒绝', () => {
  assert.equal(pna.parseIPv4('127.0.0.1'), 0x7f000001);
  assert.equal(pna.parseIPv4('192.168.1.10'), 0xc0a8010a);
  assert.equal(pna.parseIPv4('256.1.1.1'), null);
  assert.equal(pna.parseIPv4('01.2.3.4'), null); // 前导零（八进制歧义）
  assert.equal(pna.parseIPv4('a.b.c.d'), null);
});

test('classifyHost IPv4 地址空间', () => {
  assert.equal(pna.classifyHost('127.0.0.1'), SPACE_LOOPBACK);
  assert.equal(pna.classifyHost('127.99.88.77'), SPACE_LOOPBACK);
  assert.equal(pna.classifyHost('10.0.0.5'), SPACE_PRIVATE);
  assert.equal(pna.classifyHost('192.168.1.1'), SPACE_PRIVATE);
  assert.equal(pna.classifyHost('172.16.0.1'), SPACE_PRIVATE);
  assert.equal(pna.classifyHost('172.31.255.255'), SPACE_PRIVATE);
  assert.equal(pna.classifyHost('172.32.0.1'), SPACE_PUBLIC);
  assert.equal(pna.classifyHost('172.15.0.1'), SPACE_PUBLIC);
  assert.equal(pna.classifyHost('169.254.169.254'), SPACE_LINK_LOCAL); // 云元数据
  assert.equal(pna.classifyHost('100.64.0.1'), SPACE_LINK_LOCAL);    // CGNAT
  assert.equal(pna.classifyHost('8.8.8.8'), SPACE_PUBLIC);
});

// ===== IPv6 =====

test('classifyHost IPv6 环回/私网/链路本地', () => {
  assert.equal(pna.classifyHost('[::1]'), SPACE_LOOPBACK);
  assert.equal(pna.classifyHost('::1'), SPACE_LOOPBACK);
  assert.equal(pna.classifyHost('[fd00::1]'), SPACE_PRIVATE);
  assert.equal(pna.classifyHost('[fe80::1]'), SPACE_LINK_LOCAL);
  assert.equal(pna.classifyHost('[2606:4700::1]'), SPACE_PUBLIC);
});

test('IPv4-mapped IPv6 按 v4 分类', () => {
  assert.equal(pna.classifyHost('[::ffff:192.168.0.1]'), SPACE_PRIVATE);
  assert.equal(pna.classifyHost('[::ffff:127.0.0.1]'), SPACE_LOOPBACK);
  assert.equal(pna.classifyHost('[::ffff:8.8.8.8]'), SPACE_PUBLIC);
});

test('localhost 名称视为环回，普通域名 UNKNOWN', () => {
  assert.equal(pna.classifyHost('localhost'), SPACE_LOOPBACK);
  assert.equal(pna.classifyHost('api.localhost'), SPACE_LOOPBACK);
  assert.equal(pna.classifyHost('example.com'), SPACE_UNKNOWN);
  assert.equal(pna.classifyHost(''), SPACE_UNKNOWN);
});

// ===== 请求级策略 =====

test('公网页面打云元数据地址被拦截', () => {
  const r = pna.evaluatePnaRequest({
    url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    resourceType: 'xhr',
    documentURL: 'https://evil.example/app',
  });
  assert.equal(r.block, true);
  assert.equal(r.reason, 'public-to-link-local');
});

test('公网页面请求路由器后台被拦截', () => {
  const r = pna.evaluatePnaRequest({
    url: 'http://192.168.1.1/cgi-bin/luci',
    resourceType: 'image',
    documentURL: 'https://ads.example/track',
  });
  assert.equal(r.block, true);
  assert.equal(r.reason, 'public-to-private');
});

test('公网页面请求本机服务被拦截', () => {
  const r = pna.evaluatePnaRequest({
    url: 'http://127.0.0.1:8080/admin',
    resourceType: 'fetch',
    documentURL: 'https://evil.example/',
  });
  // 'fetch' 不在集合里（Electron 用 xhr），用 xhr 再测
  assert.equal(r.block, false);
  const r2 = pna.evaluatePnaRequest({
    url: 'http://localhost:3000/secret',
    resourceType: 'xhr',
    documentURL: 'https://evil.example/',
  });
  assert.equal(r2.block, true);
  assert.equal(r2.reason, 'public-to-loopback');
});

test('顶层导航永不拦截', () => {
  const r = pna.evaluatePnaRequest({
    url: 'http://192.168.1.1/',
    resourceType: 'mainFrame',
    documentURL: 'https://evil.example/',
  });
  assert.equal(r.block, false);
  assert.equal(r.reason, 'main-frame');
});

test('私网页面自己访问私网放行', () => {
  const r = pna.evaluatePnaRequest({
    url: 'http://192.168.1.5/api',
    resourceType: 'xhr',
    documentURL: 'http://192.168.1.10/dashboard',
  });
  assert.equal(r.block, false);
  assert.equal(r.reason, 'private-initiator');
});

test('公网目标放行、非 http 放行、关闭开关放行', () => {
  assert.equal(pna.evaluatePnaRequest({
    url: 'https://cdn.example.com/a.js', resourceType: 'script',
    documentURL: 'https://evil.example/',
  }).block, false);
  assert.equal(pna.evaluatePnaRequest({
    url: 'file:///C:/Windows/win.ini', resourceType: 'xhr',
    documentURL: 'https://evil.example/',
  }).block, false);
  assert.equal(pna.evaluatePnaRequest({
    url: 'http://192.168.1.1/', resourceType: 'xhr',
    documentURL: 'https://evil.example/',
  }, { enabled: false }).block, false);
});

test('域名形式的目标在解析前不拦（UNKNOWN 放行，避免 DNS 误杀）', () => {
  const r = pna.evaluatePnaRequest({
    url: 'http://router.local/admin', resourceType: 'xhr',
    documentURL: 'https://evil.example/',
  });
  assert.equal(r.block, false);
  assert.equal(r.targetLevel, SPACE_UNKNOWN);
});
