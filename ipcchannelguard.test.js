'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const g = require('./ipcchannelguard');

test('通道名形态', () => {
  assert.equal(g.isValidChannelName('open-cosy-tab'), true);
  assert.equal(g.isValidChannelName(''), false);
  assert.equal(g.isValidChannelName(123), false);
  assert.equal(g.isValidChannelName('a\nb'), false);
  assert.equal(g.isValidChannelName('x'.repeat(g.MAX_CHANNEL_CHARS + 1)), false);
  assert.equal(g.hasControlChar('a\u0000b'), true);
});

test('非白名单通道阻断（async/sync）', () => {
  const st = g.createIpcChannelState();
  const a = g.evaluateIpcChannel({ channel: 'evil-chan', kind: 'async', argsLength: 0 }, new Set(), st, 100);
  assert.equal(a.action, g.IPC_BLOCK);
  assert.ok(a.reasons.includes('channel-not-allowlisted'));
  const s = g.evaluateIpcChannel({ channel: 'evil-chan', kind: 'sync', argsLength: 0 }, new Set(), st, 101);
  assert.equal(s.action, g.IPC_BLOCK);
  assert.equal(s.kind, g.IPC_SYNC);
});

test('白名单通道在限额内放行', () => {
  const st = g.createIpcChannelState();
  const allow = new Set(['trusted-raw']);
  const v = g.evaluateIpcChannel({ channel: 'trusted-raw', kind: 'async', argsLength: 2 }, allow, st, 100);
  assert.equal(v.action, g.IPC_ALLOW);
  assert.deepEqual(v.reasons, []);
});

test('默认 kind 归为 async', () => {
  const st = g.createIpcChannelState();
  const v = g.evaluateIpcChannel({ channel: 'x' }, new Set(), st, 100);
  assert.equal(v.kind, g.IPC_ASYNC);
});

test('畸形通道名阻断且不计数频率窗', () => {
  const st = g.createIpcChannelState();
  const v = g.evaluateIpcChannel({ channel: 42, kind: 'sync' }, new Set(), st, 100);
  assert.equal(v.action, g.IPC_BLOCK);
  assert.ok(v.reasons.includes('bad-channel-name'));
  assert.equal(st.syncBurstCount, 0);
});

test('同步参数过多阻断', () => {
  const st = g.createIpcChannelState();
  const allow = new Set(['sync-ok']);
  const v = g.evaluateIpcChannel(
    { channel: 'sync-ok', kind: 'sync', argsLength: g.MAX_SYNC_ARGS + 1 }, allow, st, 100);
  assert.equal(v.action, g.IPC_BLOCK);
  assert.ok(v.reasons.includes('sync-args-overflow'));
});

test('async 参数上限独立', () => {
  const st = g.createIpcChannelState();
  const allow = new Set(['a']);
  const over = g.evaluateIpcChannel(
    { channel: 'a', kind: 'async', argsLength: g.MAX_ASYNC_ARGS + 1 }, allow, st, 100);
  assert.ok(over.reasons.includes('args-overflow'));
  const ok = g.evaluateIpcChannel(
    { channel: 'a', kind: 'async', argsLength: g.MAX_ASYNC_ARGS }, allow, st, 200);
  assert.equal(ok.action, g.IPC_ALLOW);
});

test('同步高频触发冷却（从严阈值）', () => {
  const st = g.createIpcChannelState();
  const allow = new Set(['s']);
  let cooled = false;
  for (let i = 0; i < g.SYNC_BURST_MAX + 1; i++) {
    const v = g.evaluateIpcChannel({ channel: 's', kind: 'sync', argsLength: 0 }, allow, st, 10);
    if (v.reasons.includes('ipc-channel-flood')) cooled = true;
  }
  assert.equal(cooled, true);
});

test('async 阈值远高于 sync', () => {
  assert.ok(g.ASYNC_BURST_MAX > g.SYNC_BURST_MAX);
  const st = g.createIpcChannelState();
  const allow = new Set(['a']);
  let blocked = false;
  for (let i = 0; i < g.SYNC_BURST_MAX + 2; i++) {
    const v = g.evaluateIpcChannel({ channel: 'a', kind: 'async', argsLength: 0 }, allow, st, 10);
    if (v.action === g.IPC_BLOCK) blocked = true;
  }
  assert.equal(blocked, false);
});

test('冷却期白名单通道也阻断', () => {
  const st = g.createIpcChannelState();
  const allow = new Set(['s']);
  for (let i = 0; i < g.SYNC_BURST_MAX + 1; i++) {
    g.evaluateIpcChannel({ channel: 's', kind: 'sync' }, allow, st, 10);
  }
  const v = g.evaluateIpcChannel({ channel: 's', kind: 'sync' }, allow, st, 11);
  assert.equal(v.action, g.IPC_BLOCK);
  assert.ok(v.reasons.includes('ipc-channel-flood'));
});

test('resetForNavigation 清零', () => {
  const st = g.createIpcChannelState();
  const allow = new Set(['a']);
  g.evaluateIpcChannel({ channel: 'a', kind: 'async' }, allow, st, 100);
  g.resetForNavigation(st);
  assert.equal(st.asyncBurstCount, 0);
  assert.equal(st.cooldownUntil, 0);
  // total/blocked 累计观测保留。
  assert.equal(st.total, 1);
});

test('空 input / 非 Set 白名单安全', () => {
  const st = g.createIpcChannelState();
  const v = g.evaluateIpcChannel(null, null, st, 100);
  assert.equal(v.action, g.IPC_BLOCK);
  assert.ok(v.reasons.includes('bad-channel-name'));
});
