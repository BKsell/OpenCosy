'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const r = require('./referrerleakguard');

test('同源 https 发完整', () => {
  const out = r.decideReferrer('https://a.com/x?y=1', 'https://a.com/z');
  assert.equal(out.mode, 'full');
});

test('https -> http 降级完全不发', () => {
  const out = r.decideReferrer('https://a.com/x', 'http://evil.com/');
  assert.equal(out.mode, 'none');
});

test('跨域 https 只发 origin', () => {
  const out = r.decideReferrer('https://a.com/x?y=1', 'https://b.com/');
  assert.equal(out.mode, 'origin');
  assert.equal(out.value, 'https://a.com');
});

test('本地来源绝不发 Referer', () => {
  for (const s of ['file:///c:/x', 'about:blank', 'chrome-extension://abc/x']) {
    const out = r.decideReferrer(s, 'https://evil.com/');
    assert.equal(out.mode, 'none', s);
  }
});

test('非法 URL 不发', () => {
  const out = r.decideReferrer('not a url', 'https://b.com/');
  assert.equal(out.mode, 'none');
});

test('敏感查询串识别', () => {
  assert.equal(r.shouldStripSensitiveQuery('https://a.com/?token=abc'), true);
  assert.equal(r.shouldStripSensitiveQuery('https://a.com/?api_key=abc'), true);
  assert.equal(r.shouldStripSensitiveQuery('https://a.com/?page=1'), false);
});

test('parseOrigin 与 secure 判定', () => {
  assert.equal(r.parseOrigin('https://a.com/x'), 'https://a.com');
  assert.equal(r.isSecureUrl('HTTP://a.com'), false);
  assert.equal(r.isLocalSource('data:text/html,x'), true);
});
