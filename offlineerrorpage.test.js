'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const o = require('./offlineerrorpage');

test('isOffline 优先', () => {
  const r = o.classifyNetworkError({ errorCode: '-105', isOffline: true });
  assert.equal(r.category, 'offline');
});

test('DNS 失败', () => {
  const r = o.classifyNetworkError({ errorCode: 'ERR_NAME_NOT_RESOLVED' });
  assert.equal(r.category, 'dns');
});

test('证书错误不可重试', () => {
  const r = o.classifyNetworkError({ errorCode: 'ERR_CERT_AUTHORITY_INVALID' });
  assert.equal(r.category, 'cert');
  assert.equal(r.retryable, false);
});

test('连接重置', () => {
  const r = o.classifyNetworkError({ errorCode: 'ERR_CONNECTION_RESET' });
  assert.equal(r.category, 'reset');
});

test('超时', () => {
  const r = o.classifyNetworkError({ errorCode: '-118' });
  assert.equal(r.category, 'timeout');
});

test('未知错误兜底', () => {
  const r = o.classifyNetworkError({ errorCode: 'WEIRD' });
  assert.equal(r.category, 'unknown');
});

test('退避重试类别', () => {
  assert.equal(o.isRetryableAfterBackoff('dns'), true);
  assert.equal(o.isRetryableAfterBackoff('cert'), false);
});
