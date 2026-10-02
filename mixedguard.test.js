'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const mg = require('./mixedguard');

test('主动混合内容在 https 页面中被阻止', () => {
  const page = 'https://shop.example.com/';
  const active = [
    ['http://cdn.example.com/app.js', 'script'],
    ['http://api.example.com/data', 'xhr'],
    ['http://frame.example.com/', 'subFrame'],
    ['http://css.example.com/a.css', 'stylesheet'],
    ['http://plugin.example.com/x.swf', 'object'],
    ['ws://socket.example.com/feed', 'webSocket'],
  ];
  for (const [url, type] of active) {
    const r = mg.classifyMixedContent(url, page, type);
    assert.equal(r.action, 'block', `${type} ${url} 应阻止`);
    assert.ok(r.reason);
  }
});

test('被动混合内容在 https 页面中升级到 https', () => {
  const page = 'https://news.example.com/';
  const passive = [
    ['http://img.example.com/a.png', 'image'],
    ['http://img.example.com/a@2x.png', 'imageset'],
    ['http://media.example.com/v.mp4', 'media'],
    ['http://fonts.example.com/f.woff2', 'font'],
    ['http://beacon.example.com/p', 'ping'],
  ];
  for (const [url, type] of passive) {
    const r = mg.classifyMixedContent(url, page, type);
    assert.equal(r.action, 'upgrade', `${type} 应升级`);
    assert.ok(r.upgrade && r.upgrade.startsWith('https://'), '升级目标必须是 https');
  }
});

test('顶层 http 导航不属本策略，交给 HTTPS-only', () => {
  const r = mg.classifyMixedContent('http://example.com/', 'https://example.com/', 'mainFrame');
  assert.equal(r.action, 'allow');
  assert.equal(r.reason, 'toplevel-navigation');
});

test('http 页面里的 http 子资源不算混合内容', () => {
  const r = mg.classifyMixedContent('http://cdn.example.com/a.js', 'http://example.com/', 'script');
  assert.equal(r.action, 'allow');
  assert.equal(r.reason, 'insecure-page');
});

test('https 子资源在 https 页面中放行', () => {
  const r = mg.classifyMixedContent('https://cdn.example.com/a.js', 'https://example.com/', 'script');
  assert.equal(r.action, 'allow');
  assert.equal(r.reason, 'secure-resource');
});

test('回环明文资源豁免，方便本地联调', () => {
  const page = 'https://localhost:8443/';
  for (const [url, type] of [
    ['http://localhost:3000/hot.js', 'script'],
    ['http://127.0.0.1:3000/hot.js', 'script'],
    ['http://[::1]:3000/hot.js', 'script'],
    ['http://dev.localhost/x.js', 'xhr'],
  ]) {
    const r = mg.classifyMixedContent(url, page, type);
    assert.equal(r.action, 'allow', `${url} 应豁免`);
    assert.equal(r.reason, 'loopback-exempt');
  }
  // 公网明文不豁免。
  const pub = mg.classifyMixedContent('http://evil.example.com/a.js', page, 'script');
  assert.equal(pub.action, 'block');
});

test('未归类资源类型刻意放行，交给 Chromium 自身策略', () => {
  // 'other'（含部分扩展/内部请求）不武断阻断，避免误伤；ws 的权威类型是 webSocket。
  const r = mg.classifyMixedContent('http://s.example.com/x', 'https://example.com/', 'other');
  assert.equal(r.action, 'allow');
  assert.equal(r.reason, 'unclassified-type');
  const r2 = mg.classifyMixedContent('ws://s.example.com/', 'https://example.com/', 'webSocket');
  assert.equal(r2.action, 'block');
  assert.equal(r2.reason, 'active-websocket');
});

test('非法 URL 安全放行而非抛错', () => {
  assert.equal(mg.classifyMixedContent('not a url', 'https://e.com/', 'script').action, 'allow');
  assert.equal(mg.classifyMixedContent('', 'https://e.com/', 'script').action, 'allow');
  assert.equal(mg.classifyMixedContent('http://x/a.js', '', 'script').action, 'allow');
});

test('upgradedURL 只升级 http', () => {
  assert.equal(mg.upgradedURL('http://a.com/x'), 'https://a.com/x');
  assert.equal(mg.upgradedURL('https://a.com/x'), '');
  assert.equal(mg.upgradedURL('bad url'), '');
});

test('集合分类边界稳定', () => {
  assert.ok(mg.ACTIVE_TYPES.has('script'));
  assert.ok(mg.PASSIVE_TYPES.has('image'));
  assert.ok(mg.TOPLEVEL_TYPES.has('mainFrame'));
  assert.equal(mg.pageIsSecure('wss://x/'), true);
  assert.equal(mg.pageIsSecure('http://x/'), false);
  assert.equal(mg.isInsecureSubresourceScheme('ws://x/'), true);
  assert.equal(mg.isInsecureSubresourceScheme('https://x/'), false);
});
