'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const w = require('./webworkerfileorigin');

test('同源 https Worker 放行', () => {
  const r = w.shouldAllowWorkerOrigin({
    pageUrl: 'https://a.com/x',
    workerUrl: 'https://a.com/w.js',
  });
  assert.equal(r.allow, true);
});

test('跨域 Worker 拦截', () => {
  const r = w.shouldAllowWorkerOrigin({
    pageUrl: 'https://a.com/x',
    workerUrl: 'https://evil.com/w.js',
  });
  assert.equal(r.allow, false);
  assert.equal(r.reason, 'cross-origin-worker');
});

test('data: Worker 默认拦截', () => {
  const r = w.shouldAllowWorkerOrigin({
    pageUrl: 'https://a.com/x',
    workerUrl: 'data:application/javascript,console.log(1)',
  });
  assert.equal(r.allow, false);
});

test('file: 页面 Worker 拦截', () => {
  const r = w.shouldAllowWorkerOrigin({
    pageUrl: 'file:///C:/x.html',
    workerUrl: 'https://a.com/w.js',
  });
  assert.equal(r.allow, false);
});

test('坏 URL 拦截', () => {
  const r = w.shouldAllowWorkerOrigin({ pageUrl: '://nope', workerUrl: 'x' });
  assert.equal(r.allow, false);
});
