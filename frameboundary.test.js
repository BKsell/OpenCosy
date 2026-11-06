'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const boundary = require('./frameboundary');

test('originOf 只接受 http(s) 站点', () => {
  assert.equal(boundary.originOf('https://Example.COM/a?b=1'), 'https://example.com');
  assert.equal(boundary.originOf('data:text/html,hi'), '');
  assert.equal(boundary.originOf('not a url'), '');
});

test('isSameOrigin 对端口与主机敏感', () => {
  assert.equal(boundary.isSameOrigin('https://a.test/x', 'https://a.test/y'), true);
  assert.equal(boundary.isSameOrigin('https://a.test:8443/x', 'https://a.test/y'), false);
  assert.equal(boundary.isSameOrigin('http://a.test/x', 'https://a.test/y'), false);
});

test('isSecureUrl 允许 https 与本地明文', () => {
  assert.equal(boundary.isSecureUrl('https://example.com'), true);
  assert.equal(boundary.isSecureUrl('http://localhost:3000'), true);
  assert.equal(boundary.isSecureUrl('http://example.com'), false);
  assert.equal(boundary.isSecureUrl('about:blank'), false);
});

test('inspectFrame 标记跨源子框架', () => {
  const frame = boundary.inspectFrame({
    requestUrl: 'https://ads.test/frame',
    topUrl: 'https://site.test/page',
    isMainFrame: false,
  });
  assert.equal(frame.sameOrigin, false);
  assert.ok(frame.reasons.includes('cross-origin-frame'));
  assert.equal(frame.topFrame, false);
});

test('inspectFrame 标记失焦标签与窗口', () => {
  const frame = boundary.inspectFrame({
    requestUrl: 'https://site.test/',
    topUrl: 'https://site.test/',
    tabActive: false,
    windowFocused: false,
  });
  assert.deepEqual(frame.reasons.sort(), ['tab-inactive', 'window-unfocused']);
  assert.equal(boundary.blockingFrameReasons(frame).length, 2);
});

test('inspectFrame 明文只算告警原因', () => {
  const frame = boundary.inspectFrame({
    requestUrl: 'http://site.test/',
    topUrl: 'http://site.test/',
  });
  assert.ok(frame.reasons.includes('insecure-transport'));
  assert.equal(boundary.blockingFrameReasons(frame).length, 0);
});

test('blockingFrameReasons 对缺失 URL 生效', () => {
  const frame = boundary.inspectFrame({ requestUrl: '', topUrl: 'https://site.test/' });
  assert.deepEqual(boundary.blockingFrameReasons(frame), ['missing-url']);
});

test('hostOf 小写返回主机名', () => {
  assert.equal(boundary.hostOf('https://Sub.Site.Test/x'), 'sub.site.test');
  assert.equal(boundary.hostOf('garbage'), '');
});

test('isLocalHostName 识别回环别名', () => {
  assert.equal(boundary.isLocalHostName('localhost'), true);
  assert.equal(boundary.isLocalHostName('foo.localhost'), true);
  assert.equal(boundary.isLocalHostName('example.com'), false);
});

test('describeFrame 汇总原因', () => {
  const frame = boundary.inspectFrame({ requestUrl: '', topUrl: '' });
  assert.equal(boundary.describeFrame(frame), 'missing-url');
});
