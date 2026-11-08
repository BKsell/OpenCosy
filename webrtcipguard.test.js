'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const w = require('./webrtcipguard');

test('非安全上下文拦', () => {
  const r = w.decideWebRTC({ hasUserGesture: true, isSecureContext: false, policy: 'allow' });
  assert.equal(r.action, 'block');
});

test('block-all 策略', () => {
  const r = w.decideWebRTC({ hasUserGesture: true, isSecureContext: true, policy: 'block-all' });
  assert.equal(r.action, 'block');
});

test('默认策略无手势拦', () => {
  const r = w.decideWebRTC({ hasUserGesture: false, isSecureContext: true, policy: 'block-local-candidates' });
  assert.equal(r.action, 'block');
});

test('有手势默认策略放行但静音本地候选', () => {
  const r = w.decideWebRTC({ hasUserGesture: true, isSecureContext: true, policy: 'block-local-candidates' });
  assert.equal(r.action, 'allow');
  assert.equal(r.localCandidates, 'muted');
});

test('allow 策略全放', () => {
  const r = w.decideWebRTC({ hasUserGesture: false, isSecureContext: true, policy: 'allow' });
  assert.equal(r.action, 'allow');
  assert.equal(r.localCandidates, 'allow');
});

test('本地候选识别', () => {
  assert.equal(w.isLocalCandidateAddress('192.168.1.5'), true);
  assert.equal(w.isLocalCandidateAddress('10.0.0.2'), true);
  assert.equal(w.isLocalCandidateAddress('172.16.0.1'), true);
  assert.equal(w.isLocalCandidateAddress('172.32.0.1'), false);
  assert.equal(w.isLocalCandidateAddress('8.8.8.8'), false);
  assert.equal(w.isLocalCandidateAddress('::1'), true);
  assert.equal(w.isLocalCandidateAddress('host.local'), true);
});

test('过滤本地候选列表', () => {
  const in_ = [
    'candidate:1 1 udp 1 192.168.1.5 54321 typ host',
    'candidate:2 1 udp 1 8.8.8.8 54321 typ srflx',
    'candidate:3 1 udp 1 [::1] 54321 typ host',
  ];
  const out = w.filterLocalCandidates(in_);
  assert.equal(out.length, 1);
  assert.match(out[0], /8\.8\.8\.8/);
});

test('过滤空/非数组', () => {
  assert.deepEqual(w.filterLocalCandidates(null), []);
  assert.deepEqual(w.filterLocalCandidates([]), []);
});
