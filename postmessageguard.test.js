'use strict';

// postmessageguard.test.js —— 覆盖 origin 解析、白名单精确/后缀匹配、
// 端口/协议、null origin、data 结构安全、频道白名单与外发 wildcard 检查。

const test = require('node:test');
const assert = require('node:assert/strict');
const pm = require('./postmessageguard');
const {
  parseOrigin,
  hostMatchesSuffix,
  originAllowed,
  inspectMessageData,
  decideIncoming,
  auditOutgoing,
  buildPolicy,
} = pm;

test('parseOrigin 解析标准 origin 与 IPv6/端口', () => {
  assert.deepEqual(parseOrigin('https://app.example.com'), { scheme: 'https', host: 'app.example.com', port: 0 });
  assert.deepEqual(parseOrigin('http://localhost:8080'), { scheme: 'http', host: 'localhost', port: 8080 });
  assert.equal(parseOrigin('https://[::1]:9000').host, '[::1]');
  assert.equal(parseOrigin('https://a.com/path'), null);
  assert.equal(parseOrigin('javascript:alert(1)'), null);
  assert.equal(parseOrigin('https://a.com:99999'), null);
  assert.equal(parseOrigin(''), null);
});

test('后缀匹配受控，防 evilpaypal 绕过', () => {
  assert.equal(hostMatchesSuffix('paypal.com.evil.net', 'paypal.com'), false);
  assert.equal(hostMatchesSuffix('evilpaypal.com', 'paypal.com'), false);
  assert.equal(hostMatchesSuffix('accounts.paypal.com', '.paypal.com'), true);
  assert.equal(hostMatchesSuffix('paypal.com', 'paypal.com'), true);
});

test('白名单 origin 精确与后缀放行', () => {
  const p = buildPolicy({
    allowedOrigins: ['https://exact.example.com'],
    allowedHostSuffixes: ['.trusted.org'],
  });
  assert.equal(originAllowed('https://exact.example.com', p).ok, true);
  assert.equal(originAllowed('https://sub.trusted.org', p).ok, true);
  assert.equal(originAllowed('https://trusted.org.evil.net', p).ok, false);
  assert.equal(originAllowed('https://evil.org', p).ok, false);
});

test('http 默认拒绝，localhost http 需显式开关', () => {
  assert.equal(originAllowed('http://example.com', buildPolicy()).reason, 'insecure-scheme');
  const withLocal = buildPolicy({ allowLocalhostHttp: true });
  assert.equal(originAllowed('http://127.0.0.1:8080', withLocal).ok, true);
  assert.equal(originAllowed('http://example.com', withLocal).reason, 'insecure-scheme');
});

test('非白名单端口拒绝', () => {
  const p = buildPolicy({ allowedOrigins: ['https://a.com'], allowedPorts: [8443] });
  assert.equal(originAllowed('https://a.com:8443', p).ok, true);
  assert.equal(originAllowed('https://a.com:9000', p).reason, 'port-not-allowed');
});

test('字符串 null origin 默认拒绝', () => {
  assert.equal(originAllowed('null', buildPolicy()).reason, 'null-origin');
  assert.equal(originAllowed('null', buildPolicy({ allowNullOrigin: true })).ok, true);
});

test('data 原型键/深度/键数/字节 检查', () => {
  const p = buildPolicy();
  const ownProto = Object.create(null);
  ownProto.__proto__ = 1;
  assert.equal(inspectMessageData(ownProto, p), 'prototype-key');
  assert.equal(inspectMessageData({ a: { constructor: 1 } }, p), 'prototype-key');

  let deep = { v: 1 };
  for (let i = 0; i < p.maxDepth + 2; i++) deep = { v: deep };
  assert.equal(inspectMessageData(deep, p), 'data-too-deep');

  const many = {};
  for (let i = 0; i < p.maxKeys + 1; i++) many['k' + i] = 1;
  assert.equal(inspectMessageData(many, p), 'data-too-many-keys');

  assert.equal(inspectMessageData({ s: 'x'.repeat(p.maxPayloadBytes + 1) }, p), 'data-too-large');
  assert.equal(inspectMessageData({ f: () => 1 }, p), 'data-illegal-type');
});

test('decideIncoming 完整链路', () => {
  const p = buildPolicy({
    allowedOrigins: ['https://app.example.com'],
    allowedChannels: ['ready', 'sync'],
  });
  assert.equal(decideIncoming({ origin: 'https://app.example.com', data: { channel: 'ready' } }, p).allow, true);
  const badOrigin = decideIncoming({ origin: 'https://evil.com', data: { channel: 'ready' } }, p);
  assert.equal(badOrigin.allow, false);
  assert.equal(badOrigin.reason, 'origin-not-whitelisted');
  const badChan = decideIncoming({ origin: 'https://app.example.com', data: { channel: 'exec' } }, p);
  assert.equal(badChan.allow, false);
  assert.equal(badChan.reason, 'channel-not-whitelisted');
});

test('decideIncoming 拒绝原型污染载荷', () => {
  const p = buildPolicy({ allowedOrigins: ['https://app.example.com'] });
  const r = decideIncoming({ origin: 'https://app.example.com', data: JSON.parse('{"__proto__":{"x":1}}') }, p);
  assert.equal(r.allow, false);
  assert.equal(r.reason, 'prototype-key');
});

test('decideIncoming 接受短字符串握手', () => {
  const p = buildPolicy({ allowedOrigins: ['https://app.example.com'] });
  assert.equal(decideIncoming({ origin: 'https://app.example.com', data: 'ping' }, p).allow, true);
  const tooLong = decideIncoming({ origin: 'https://app.example.com', data: 'x'.repeat(99999) }, p);
  assert.equal(tooLong.allow, false);
});

test('外发 wildcard 带敏感字段被拒', () => {
  assert.equal(auditOutgoing('*', { token: 'abc' }, ['token']).ok, false);
  assert.equal(auditOutgoing('*', { user: { password: '1' } }, ['password']).reason, 'sensitive-on-wildcard');
  assert.equal(auditOutgoing('*', { a: 1 }, ['token']).ok, true);
  assert.equal(auditOutgoing('*', null, ['token']).ok, true);
});

test('外发具体 origin 必须可解析', () => {
  assert.equal(auditOutgoing('javascript:x', {}).ok, false);
  assert.equal(auditOutgoing('https://app.example.com', {}).ok, true);
  assert.equal(auditOutgoing('', {}).reason, 'empty-target-origin');
});
