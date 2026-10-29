'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const w = require('./webtransportorigin');

test('非 https 拦', () => {
  const r = w.decideWebTransport({ urlStr: 'http://example.com/x', hasUserGesture: true });
  assert.equal(r.action, 'block');
});

test('无手势拦', () => {
  const r = w.decideWebTransport({ urlStr: 'https://example.com/x', hasUserGesture: false });
  assert.equal(r.action, 'block');
});

test('内网主机拦', () => {
  const r = w.decideWebTransport({ urlStr: 'https://192.168.1.5:4433/x', hasUserGesture: true });
  assert.equal(r.action, 'block');
});

test('localhost 拦', () => {
  const r = w.decideWebTransport({ urlStr: 'https://localhost:4433/x', hasUserGesture: true });
  assert.equal(r.action, 'block');
});

test('公网 allow', () => {
  const r = w.decideWebTransport({ urlStr: 'https://cdn.example.com/x', hasUserGesture: true });
  assert.equal(r.action, 'allow');
});

test('坏 URL 拦', () => {
  const r = w.decideWebTransport({ urlStr: '://nope', hasUserGesture: true });
  assert.equal(r.action, 'block');
});

test('自定义 privateHosts 注入', () => {
  const r = w.decideWebTransport({
    urlStr: 'https://internal.corp/x',
    hasUserGesture: true,
    privateHosts: (h) => h.endsWith('.corp'),
  });
  assert.equal(r.action, 'block');
});

test('isPrivateHost', () => {
  assert.equal(w.isPrivateHost('10.0.0.1'), true);
  assert.equal(w.isPrivateHost('172.16.0.1'), true);
  assert.equal(w.isPrivateHost('172.32.0.1'), false);
  assert.equal(w.isPrivateHost('8.8.8.8'), false);
});

test('parseTransportTarget 拆 URL', () => {
  const r = w.parseTransportTarget('https://cdn.example.com:4433/x');
  assert.deepEqual(r, { scheme: 'https', host: 'cdn.example.com', port: '4433' });
});

test('parseTransportTarget 坏 URL 返回 null', () => {
  assert.equal(w.parseTransportTarget('://nope'), null);
  assert.equal(w.parseTransportTarget(''), null);
});
