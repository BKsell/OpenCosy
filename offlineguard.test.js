'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const off = require('./offlineguard');

test('在线时一律 normal', () => {
  const r = off.decideOfflineRequest(true, { url: 'https://a.com/x', resourceType: 'mainFrame' });
  assert.equal(r.mode, 'normal');
  assert.equal(r.showBanner, false);
});

test('离线时本地来源放行且不提示', () => {
  for (const u of ['file:///c:/x', 'data:text/html,x', 'chrome-extension://abc/x', 'about:blank']) {
    const r = off.decideOfflineRequest(false, { url: u, resourceType: 'mainFrame' });
    assert.equal(r.mode, 'local', u);
    assert.equal(r.showBanner, false, u);
  }
});

test('离线时顶层 http(s) 导航硬拦截', () => {
  const r = off.decideOfflineRequest(false, { url: 'https://a.com/', resourceType: 'mainFrame' });
  assert.equal(r.mode, 'offline-block');
  assert.equal(r.showBanner, true);
});

test('离线时子资源软失败但仍提示横幅', () => {
  for (const rt of ['image', 'script', 'xhr', 'subFrame']) {
    const r = off.decideOfflineRequest(false, { url: 'https://a.com/i.png', resourceType: rt });
    assert.equal(r.mode, 'offline-soft', rt);
    assert.equal(r.showBanner, true, rt);
  }
});

test('schemeOf 识别常见 scheme', () => {
  assert.equal(off.schemeOf('HTTPS://A.com'), 'https:');
  assert.equal(off.schemeOf('file:///x'), 'file:');
  assert.equal(off.schemeOf('not a url'), '');
});

test('offlineBannerText 在线空、离线有文案', () => {
  assert.equal(off.offlineBannerText(true), '');
  assert.match(off.offlineBannerText(false), /网络已断开/);
});

test('白名单默认不压制任何 host', () => {
  assert.equal(off.shouldSuppressOfflineForHost('example.com'), false);
});
