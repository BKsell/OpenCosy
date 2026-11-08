'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const w = require('./wsoriginguard');

test('https 页必须 wss', () => {
  const r = w.decideWebSocket('https://a.com/', 'ws://a.com/sock', false);
  assert.equal(r.action, 'block');
  assert.equal(r.reason, 'mixed-content-ws');
});

test('http 页 ws 放行', () => {
  const r = w.decideWebSocket('http://a.com/', 'ws://a.com/sock', false);
  assert.equal(r.action, 'allow');
});

test('wss 正常跨域放行', () => {
  const r = w.decideWebSocket('https://a.com/', 'wss://b.com/sock', false);
  assert.equal(r.action, 'allow');
});

test('内网地址拦', () => {
  assert.equal(w.decideWebSocket('https://a.com/', 'wss://localhost:8080/', false).action, 'block');
  assert.equal(w.decideWebSocket('https://a.com/', 'wss://127.0.0.1/', false).action, 'block');
  assert.equal(w.decideWebSocket('https://a.com/', 'wss://service.internal/', false).action, 'block');
});

test('allowPrivate 放行', () => {
  const r = w.decideWebSocket('https://a.com/', 'wss://127.0.0.1/', true);
  assert.equal(r.action, 'allow');
});

test('坏 URL / 坏 scheme', () => {
  assert.equal(w.decideWebSocket('https://a.com/', 'not a url', false).action, 'block');
  assert.equal(w.decideWebSocket('https://a.com/', 'https://a.com/', false).action, 'block');
});

test('跨源警告', () => {
  assert.equal(w.shouldShowWsWarning('https://a.com/', 'wss://b.com/'), true);
  assert.equal(w.shouldShowWsWarning('https://a.com/', 'wss://a.com/'), false);
});
