'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const g = require('./remoteguard');

test('通道名归类', () => {
  assert.equal(g.classifyChannel('remote-require').known, true);
  assert.equal(g.classifyChannel('remote-get-global').known, true);
  assert.equal(g.classifyChannel('desktop-capturer-get-sources').known, true);
  assert.equal(g.classifyChannel('some-other').known, false);
  assert.equal(g.classifyChannel('').known, false);
  assert.equal(g.classifyChannel(null).known, false);
  assert.equal(g.isRemoteBridgeChannel('remote-get-builtin'), true);
  assert.equal(g.isRemoteBridgeChannel('x'), false);
});

test('目标名净化', () => {
  assert.equal(g.sanitizeTarget('fs').name, 'fs');
  assert.equal(g.sanitizeTarget('').name, '<empty>');
  assert.equal(g.sanitizeTarget(123).suspicious, true);
  assert.equal(g.sanitizeTarget('a\x00b').suspicious, true);
  assert.equal(g.sanitizeTarget('x'.repeat(g.MAX_TARGET_CHARS + 1)).suspicious, true);
  assert.equal(g.sanitizeTarget('electron').suspicious, false);
});

test('hasControlChar', () => {
  assert.equal(g.hasControlChar('a\nb'), true);
  assert.equal(g.hasControlChar('ok'), false);
  assert.equal(g.hasControlChar(1), false);
});

test('remote-require 恒阻断并带目标名', () => {
  const st = g.createRemoteState();
  const v = g.evaluateRemoteBridge(
    { channel: 'remote-require', target: 'child_process' }, st, 100);
  assert.equal(v.action, g.REMOTE_BLOCK);
  assert.equal(v.channel, 'remote-require');
  assert.equal(v.target, 'child_process');
  assert.equal(st.blocked, 1);
});

test('取当前窗口 / webContents / 屏幕枚举恒阻断', () => {
  const st = g.createRemoteState();
  for (const ch of [
    'remote-get-current-window',
    'remote-get-current-web-contents',
    'desktop-capturer-get-sources',
  ]) {
    const v = g.evaluateRemoteBridge({ channel: ch }, st, 100);
    assert.equal(v.action, g.REMOTE_BLOCK, ch);
    assert.equal(v.target, '', ch);
  }
});

test('畸形目标名被标记', () => {
  const st = g.createRemoteState();
  const v = g.evaluateRemoteBridge(
    { channel: 'remote-get-global', target: { evil: 1 } }, st, 100);
  assert.equal(v.action, g.REMOTE_BLOCK);
  assert.ok(v.reasons.includes('invalid-target-name'));
  assert.equal(v.target, '<non-string>');
});

test('未知通道名阻断并标记', () => {
  const st = g.createRemoteState();
  const v = g.evaluateRemoteBridge({ channel: 'weird-remote-x' }, st, 100);
  assert.equal(v.action, g.REMOTE_BLOCK);
  assert.ok(v.reasons.includes('unknown-remote-channel'));
});

test('空 input 安全', () => {
  const st = g.createRemoteState();
  const v = g.evaluateRemoteBridge(null, st, 100);
  assert.equal(v.action, g.REMOTE_BLOCK);
  assert.ok(v.reasons.includes('unknown-remote-channel'));
});

test('高频远程桥尝试触发冷却', () => {
  const st = g.createRemoteState();
  let flooded = false;
  for (let i = 0; i < g.REMOTE_BURST_MAX + 1; i++) {
    const v = g.evaluateRemoteBridge({ channel: 'remote-require', target: 'fs' }, st, 10);
    if (v.reasons.includes('remote-bridge-flood')) flooded = true;
  }
  assert.equal(flooded, true);
  // 冷却期持续阻断。
  const during = g.evaluateRemoteBridge({ channel: 'remote-require', target: 'fs' }, st, 200);
  assert.ok(during.reasons.includes('remote-bridge-flood'));
  // 冷却结束恢复计数但仍阻断。
  const after = g.evaluateRemoteBridge(
    { channel: 'remote-require', target: 'fs' }, st, 10 + g.REMOTE_COOLDOWN_MS + 1);
  assert.equal(after.action, g.REMOTE_BLOCK);
  assert.ok(!after.reasons.includes('remote-bridge-flood'));
});

test('长窗慢速累积触发冷却', () => {
  const st = g.createRemoteState();
  const step = 3000; // 3 秒一次，短窗 5s 内不超
  let flooded = false;
  for (let i = 0; i < g.REMOTE_LONG_MAX + 1; i++) {
    const v = g.evaluateRemoteBridge({ channel: 'remote-get-builtin', target: 'x' }, st, i * step);
    if (v.reasons.includes('remote-bridge-flood')) flooded = true;
  }
  assert.equal(flooded, true);
});

test('resetForNavigation 清零', () => {
  const st = g.createRemoteState();
  g.evaluateRemoteBridge({ channel: 'remote-require', target: 'fs' }, st, 100);
  g.resetForNavigation(st);
  assert.equal(st.hits > 0, true); // hits 是累计观测，保留
  assert.equal(st.burstCount, 0);
  assert.equal(st.cooldownUntil, 0);
  assert.equal(st.blocked, 1); // blocked 累计也保留
});
