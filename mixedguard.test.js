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
  assert.equal(mg.pageIsSecure('file:///C:/tmp/a.html'), true);
  assert.equal(mg.pageIsSecure('http://x/'), false);
  assert.equal(mg.isInsecureSubresourceScheme('ws://x/'), true);
  assert.equal(mg.isInsecureSubresourceScheme('https://x/'), false);
});

test('file:// 页面同样阻止明文主动混合内容', () => {
  const page = 'file:///C:/Users/me/local.html';
  const blocked = mg.classifyMixedContent('http://cdn.example.com/track.js', page, 'script');
  assert.equal(blocked.action, 'block');
  // file 页面引本地回环开发服务器仍豁免。
  const local = mg.classifyMixedContent('http://localhost:5173/app.js', page, 'script');
  assert.equal(local.action, 'allow');
  assert.equal(local.reason, 'loopback-exempt');
});

test('被动升级保留端口、路径与查询串', () => {
  const page = 'https://app.example.com/';
  const r = mg.classifyMixedContent('http://img.example.com:8443/a/b.png?v=2#x', page, 'image');
  assert.equal(r.action, 'upgrade');
  const u = new URL(r.upgrade);
  assert.equal(u.protocol, 'https:');
  assert.equal(u.host, 'img.example.com:8443');
  assert.equal(u.pathname, '/a/b.png');
  assert.equal(u.search, '?v=2');
  assert.equal(u.hash, '#x');
});

test('wss 页面里的 ws 子资源作为主动混合内容被阻止', () => {
  const r = mg.classifyMixedContent('ws://socket.example.com/live', 'wss://app.example.com/', 'webSocket');
  assert.equal(r.action, 'block');
  assert.equal(r.reason, 'active-websocket');
});

test('about:/data: 等无继承信息的顶层文档不武断拦截', () => {
  // 这些上下文的真实安全性继承自创建者，webRequest 拿不到创建者，
  // 交给 Chromium 自身判定，避免误伤。
  for (const page of ['about:blank', 'data:text/html,<h1>x', 'blob:https://e.com/abc']) {
    const r = mg.classifyMixedContent('http://cdn.example.com/a.js', page, 'script');
    assert.equal(r.action, 'allow', `${page} 不应由本层拦截`);
  }
});

test('data:/blob: 子资源本身不是明文，直接放行', () => {
  const page = 'https://example.com/';
  assert.equal(mg.classifyMixedContent('data:image/png;base64,AAAA', page, 'image').action, 'allow');
  assert.equal(mg.classifyMixedContent('blob:https://example.com/uuid', page, 'media').action, 'allow');
});
