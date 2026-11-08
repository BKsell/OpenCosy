'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const g = require('./captureguard');

test('capture id 合法性', () => {
  assert.equal(g.isValidCaptureId(''), true);
  assert.equal(g.isValidCaptureId('123'), true);
  assert.equal(g.isValidCaptureId('tab-capture-abc'), true);
  assert.equal(g.isValidCaptureId(null), false);
  assert.equal(g.isValidCaptureId(123), false);
  assert.equal(g.isValidCaptureId('a\x00b'), false);
  assert.equal(g.isValidCaptureId('x'.repeat(g.CAPTURE_MAX_ID_CHARS + 1)), false);
});

test('normalizeCaptureInfo 形态收敛', () => {
  assert.deepEqual(g.normalizeCaptureInfo(null), { hasAudio: false, hasVideo: true });
  assert.deepEqual(g.normalizeCaptureInfo({ hasAudio: true, hasVideo: false }),
    { hasAudio: true, hasVideo: false });
  assert.deepEqual(g.normalizeCaptureInfo({ hasAudio: 'yes' }),
    { hasAudio: false, hasVideo: true });
});

test('进入捕获产出 signal', () => {
  const st = g.createCaptureState(0);
  const v = g.evaluateCaptureChange(st, 'cap-1', { hasAudio: true }, 100);
  assert.equal(v.action, g.CAPTURE_SIGNAL);
  assert.equal(v.phase, 'started');
  assert.equal(st.status, g.CAPTURE_ACTIVE);
  assert.equal(v.hasAudio, true);
});

test('停止捕获产出 stopped', () => {
  const st = g.createCaptureState(0);
  g.evaluateCaptureChange(st, 'cap-1', null, 100);
  const v = g.evaluateCaptureChange(st, '', null, 200);
  assert.equal(v.action, g.CAPTURE_SIGNAL);
  assert.equal(v.phase, 'stopped');
  assert.equal(st.status, g.CAPTURE_IDLE);
});

test('空闲态重复停止幂等', () => {
  const st = g.createCaptureState(0);
  const v = g.evaluateCaptureChange(st, '', null, 100);
  assert.equal(v.action, g.CAPTURE_PASS);
  assert.equal(v.phase, 'unchanged');
  assert.equal(st.transitions, 0);
});

test('同一 id 重复上报幂等', () => {
  const st = g.createCaptureState(0);
  g.evaluateCaptureChange(st, 'cap-1', null, 100);
  const v = g.evaluateCaptureChange(st, 'cap-1', null, 150);
  assert.equal(v.action, g.CAPTURE_PASS);
  assert.equal(v.phase, 'unchanged');
  assert.equal(st.transitions, 1);
});

test('未停止直接换句柄标记 replaced', () => {
  const st = g.createCaptureState(0);
  g.evaluateCaptureChange(st, 'cap-1', null, 100);
  const v = g.evaluateCaptureChange(st, 'cap-2', null, 200);
  assert.equal(v.phase, 'replaced');
  assert.equal(v.action, g.CAPTURE_SIGNAL);
  assert.ok(v.reasons.includes('capture-handle-replaced'));
  assert.equal(st.activeId, 'cap-2');
});

test('非法 id 被丢且不改状态', () => {
  const st = g.createCaptureState(0);
  const v = g.evaluateCaptureChange(st, 42, null, 100);
  assert.equal(v.action, g.CAPTURE_DROP);
  assert.ok(v.reasons.includes('bad-capture-id'));
  assert.equal(st.status, g.CAPTURE_IDLE);
});

test('高频切换触发冷却', () => {
  const st = g.createCaptureState(0);
  let dropped = false;
  for (let i = 0; i < g.CAPTURE_BURST_MAX; i++) {
    g.evaluateCaptureChange(st, 'c' + i, null, 10);
    g.evaluateCaptureChange(st, '', null, 11);
  }
  // 上面是成对 start/stop，第 BURST 组之后再切换应被冷却拦下。
  const v = g.evaluateCaptureChange(st, 'overflow', null, 12);
  if (v.action === g.CAPTURE_DROP) dropped = true;
  assert.equal(dropped || st.cooldownUntil > 0, true);
});

test('resetForNavigation 回到空闲', () => {
  const st = g.createCaptureState(0);
  g.evaluateCaptureChange(st, 'cap-1', null, 100);
  g.resetForNavigation(st, 200);
  assert.equal(st.status, g.CAPTURE_IDLE);
  assert.equal(st.activeId, '');
  assert.equal(st.cooldownUntil, 0);
});
