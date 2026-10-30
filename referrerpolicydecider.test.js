'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const r = require('./referrerpolicydecider');

test('同源带完整 URL', () => {
  const v = r.decideReferrer({
    pageUrl: 'https://a.com/post/1',
    targetUrl: 'https://a.com/next',
    userPolicy: 'strict-origin-when-cross-origin',
  });
  assert.equal(v, 'https://a.com/post/1');
});

test('跨域只带 origin', () => {
  const v = r.decideReferrer({
    pageUrl: 'https://a.com/post/1',
    targetUrl: 'https://b.com/x',
    userPolicy: 'strict-origin-when-cross-origin',
  });
  assert.equal(v, 'https://a.com/');
});

test('https->http 不带', () => {
  const v = r.decideReferrer({
    pageUrl: 'https://a.com/post/1',
    targetUrl: 'http://b.com/x',
    userPolicy: 'strict-origin-when-cross-origin',
  });
  assert.equal(v, '');
});

test('no-referrer 不发', () => {
  const v = r.decideReferrer({
    pageUrl: 'https://a.com/x',
    targetUrl: 'https://a.com/y',
    userPolicy: 'no-referrer',
  });
  assert.equal(v, '');
});

test('隐私窗口不发', () => {
  const v = r.decideReferrer({
    pageUrl: 'https://a.com/x',
    targetUrl: 'https://a.com/y',
    userPolicy: 'strict-origin-when-cross-origin',
    isPrivateBrowsing: true,
  });
  assert.equal(v, '');
});

test('坏 URL 不发', () => {
  const v = r.decideReferrer({ pageUrl: '://x', targetUrl: 'y' });
  assert.equal(v, '');
});
