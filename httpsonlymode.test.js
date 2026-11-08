'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const h = require('./httpsonlymode');

test('HTTPS-Only 关时 pass', () => {
  const r = h.decideHttpsUpgrade({ urlStr: 'http://a.com', enabled: false });
  assert.equal(r.action, 'pass');
});

test('已经是 https pass', () => {
  const r = h.decideHttpsUpgrade({ urlStr: 'https://a.com', enabled: true });
  assert.equal(r.action, 'pass');
});

test('http 升级到 https', () => {
  const r = h.decideHttpsUpgrade({ urlStr: 'http://a.com/x', enabled: true });
  assert.equal(r.action, 'upgrade');
  assert.equal(r.upgradedUrl, 'https://a.com/x');
});

test('80 端口升级到 443', () => {
  const r = h.decideHttpsUpgrade({ urlStr: 'http://a.com:80/', enabled: true });
  // URL 对默认端口会省略端口号。
  assert.equal(r.upgradedUrl, 'https://a.com/');
});

test('localhost 放行', () => {
  const r = h.decideHttpsUpgrade({ urlStr: 'http://localhost:5173', enabled: true, allowOnLocalhost: true });
  assert.equal(r.action, 'pass');
});

test('localhost 不开放行时仍升级', () => {
  const r = h.decideHttpsUpgrade({ urlStr: 'http://localhost:5173', enabled: true });
  assert.equal(r.action, 'upgrade');
});

test('坏 URL block', () => {
  const r = h.decideHttpsUpgrade({ urlStr: '://nope', enabled: true });
  assert.equal(r.action, 'block');
});

test('file: 不动', () => {
  const r = h.decideHttpsUpgrade({ urlStr: 'file:///etc/passwd', enabled: true });
  assert.equal(r.action, 'pass');
});
