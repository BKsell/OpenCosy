'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const w = require('./webshareguard');

test('非安全上下文拦', () => {
  const r = w.decideShare(false, true, { url: 'https://a.com/' });
  assert.equal(r.action, 'block');
});

test('无用户手势拦', () => {
  const r = w.decideShare(true, false, { url: 'https://a.com/' });
  assert.equal(r.action, 'block');
});

test('空负载拦', () => {
  const r = w.decideShare(true, true, {});
  assert.equal(r.action, 'block');
});

test('http 链接拦', () => {
  const r = w.decideShare(true, true, { url: 'http://a.com/' });
  assert.equal(r.action, 'block');
});

test('https + 手势放行', () => {
  const r = w.decideShare(true, true, { title: 'hi', url: 'https://a.com/' });
  assert.equal(r.action, 'allow');
});

test('文件分享要确认，不静默放行', () => {
  const r = w.decideShare(true, true, { files: [{}] });
  assert.equal(r.action, 'block');
  assert.equal(w.shouldPromptForFiles({ files: [{}] }), true);
  assert.equal(w.shouldPromptForFiles({ text: 'x' }), false);
});

test('坏 URL 拦', () => {
  const r = w.decideShare(true, true, { url: 'not a url' });
  assert.equal(r.action, 'block');
});
