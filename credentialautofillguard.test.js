'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const g = require('./credentialautofillguard');

test('http 上下文禁止自动填充', () => {
  const d = g.decideCredentialAutofill('http://bank.com/login', 'password', false);
  assert.equal(d.allow, false);
  assert.equal(d.mode, 'off');
});

test('跨源 iframe 禁止', () => {
  const d = g.decideCredentialAutofill('https://bank.com/login', 'password', true);
  assert.equal(d.allow, false);
});

test('登录路径密码放行', () => {
  for (const p of ['https://a.com/login', 'https://a.com/signin', 'https://a.com/auth?x=1', 'https://a.com/account/signin']) {
    const d = g.decideCredentialAutofill(p, 'password', false);
    assert.equal(d.allow, true, p);
    assert.equal(d.mode, 'password');
  }
});

test('普通页面密码框拦截', () => {
  const d = g.decideCredentialAutofill('https://a.com/article/123', 'password', false);
  assert.equal(d.allow, false);
  assert.equal(g.shouldBlockPasswordPhishBox('https://a.com/'), true);
});

test('用户名框在普通页允许', () => {
  const d = g.decideCredentialAutofill('https://a.com/feed', 'username', false);
  assert.equal(d.allow, true);
  assert.equal(d.mode, 'username');
});

test('非法 URL 拒绝', () => {
  const d = g.decideCredentialAutofill('not a url', 'password', false);
  assert.equal(d.allow, false);
});

test('secure/host 工具', () => {
  assert.equal(g.isSecureContext('HTTPS://a.com'), true);
  assert.equal(g.isSecureContext('file:///x'), false);
  assert.equal(g.parseHost('https://A.COM/x'), 'a.com');
});
