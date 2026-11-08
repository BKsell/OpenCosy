'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const p = require('./pictureinpictureguard');

test('非安全上下文 deny', () => {
  const r = p.decidePip({ hasUserGesture: true, isSecureContext: false, videoDurationSec: 120 });
  assert.equal(r.action, 'deny');
});

test('无手势 deny', () => {
  const r = p.decidePip({ hasUserGesture: false, isSecureContext: true, videoDurationSec: 120 });
  assert.equal(r.action, 'deny');
});

test('极短视频 deny', () => {
  const r = p.decidePip({ hasUserGesture: true, isSecureContext: true, videoDurationSec: 0.4 });
  assert.equal(r.action, 'deny');
});

test('未信任超长视频 deny', () => {
  const r = p.decidePip({ hasUserGesture: true, isSecureContext: true, videoDurationSec: 5 * 3600, userTrusted: false });
  assert.equal(r.action, 'deny');
});

test('信任源长视频 allow', () => {
  const r = p.decidePip({ hasUserGesture: true, isSecureContext: true, videoDurationSec: 5 * 3600, userTrusted: true });
  assert.equal(r.action, 'allow');
});

test('正常短视频 allow', () => {
  const r = p.decidePip({ hasUserGesture: true, isSecureContext: true, videoDurationSec: 120, userTrusted: false });
  assert.equal(r.action, 'allow');
});

test('标签关闭自动关 PiP', () => {
  assert.equal(p.shouldAutoClosePipOnTabClose(false), true);
  assert.equal(p.shouldAutoClosePipOnTabClose(true), false);
});
