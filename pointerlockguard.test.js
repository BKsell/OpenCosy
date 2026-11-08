'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const p = require('./pointerlockguard');

test('非安全上下文拦', () => {
  const r = p.decidePointerLock(true, false, 'https://a.com/');
  assert.equal(r.action, 'block');
});

test('无手势拦', () => {
  const r = p.decidePointerLock(false, true, 'https://a.com/');
  assert.equal(r.action, 'block');
});

test('内部页拦', () => {
  assert.equal(p.decidePointerLock(true, true, 'about:blank').action, 'block');
  assert.equal(p.decidePointerLock(true, true, 'devtools://x').action, 'block');
});

test('正常页放行', () => {
  const r = p.decidePointerLock(true, true, 'https://game.example/');
  assert.equal(r.action, 'allow');
});

test('退出提示时间窗', () => {
  assert.equal(p.shouldShowExitHint(0), true);
  assert.equal(p.shouldShowExitHint(2.9), true);
  assert.equal(p.shouldShowExitHint(5), false);
});
