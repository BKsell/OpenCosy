'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const c = require('./clipboardwriteguard');

test('非安全上下文拦', () => {
  const r = c.decideClipboardWrite({ hasUserGesture: true, isSecureContext: false, targetUrl: 'https://a.com/', textLength: 10 });
  assert.equal(r.action, 'block');
});

test('无手势拦', () => {
  const r = c.decideClipboardWrite({ hasUserGesture: false, isSecureContext: true, targetUrl: 'https://a.com/', textLength: 10 });
  assert.equal(r.action, 'block');
});

test('内部页拦', () => {
  assert.equal(c.decideClipboardWrite({ hasUserGesture: true, isSecureContext: true, targetUrl: 'about:blank', textLength: 10 }).action, 'block');
  assert.equal(c.decideClipboardWrite({ hasUserGesture: true, isSecureContext: true, targetUrl: 'devtools://x', textLength: 10 }).action, 'block');
});

test('过大拦', () => {
  const r = c.decideClipboardWrite({ hasUserGesture: true, isSecureContext: true, targetUrl: 'https://a.com/', textLength: 6 * 1024 * 1024 });
  assert.equal(r.action, 'block');
});

test('正常放行', () => {
  const r = c.decideClipboardWrite({ hasUserGesture: true, isSecureContext: true, targetUrl: 'https://a.com/', textLength: 50 });
  assert.equal(r.action, 'allow');
});

test('toast 阈值', () => {
  assert.equal(c.shouldShowClipboardToast(50), false);
  assert.equal(c.shouldShowClipboardToast(500), true);
});
