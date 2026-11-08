'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  ACTION_RECORD,
  ACTION_SUPPRESS,
  DEFAULT_GPU_CRASH_COOLDOWN_MS,
  MAX_GPU_FIELD_CHARS,
  clampField,
  sanitizeGPUInfo,
  createCrashState,
  crashKey,
  decideGPUCrash,
  decideAccessibilityChange,
} = require('./gpuaccessguard');

test('clampField 去折行限长', () => {
  assert.equal(clampField('a\nb', 10), 'a b');
  const long = 'x'.repeat(MAX_GPU_FIELD_CHARS + 5);
  const got = clampField(long, MAX_GPU_FIELD_CHARS);
  assert.equal(got.length, MAX_GPU_FIELD_CHARS + 1);
  assert.ok(got.endsWith('…'));
});

test('sanitizeGPUInfo 白名单：保留安全字段，丢弃未知键', () => {
  const aux = {
    softwareRendering: true,
    canSupportVulkan: false,
    glRenderer: 'ANGLE (NVIDIA) a\nb',
    glVendor: 'Google Inc.',
    evilInternalString: 'x'.repeat(500),
    __secretHandle: 12345,
    gpuRenderingActive: 'enabled',
  };
  const r = sanitizeGPUInfo(aux);
  assert.equal(r.fields.softwareRendering, true);
  assert.equal(r.fields.canSupportVulkan, false);
  assert.equal(r.fields.glRenderer, 'ANGLE (NVIDIA) a b');
  assert.equal(r.fields.glVendor, 'Google Inc.');
  assert.equal(r.fields.gpuRenderingActive, 'enabled');
  assert.ok(!('evilInternalString' in r.fields));
  assert.ok(!('__secretHandle' in r.fields));
  assert.ok(r.dropped >= 2);
  assert.ok(r.kept >= 5);
});

test('sanitizeGPUInfo 布尔字段强制布尔化', () => {
  const r = sanitizeGPUInfo({ softwareRendering: 'truthy' });
  assert.equal(r.fields.softwareRendering, false);
});

test('sanitizeGPUInfo 非字符串/数值的白名单字符串键被丢弃', () => {
  const r = sanitizeGPUInfo({ glRenderer: { weird: 1 } });
  assert.ok(!('glRenderer' in r.fields));
  assert.equal(r.dropped, 1);
});

test('sanitizeGPUInfo 空 / 非对象不抛异常', () => {
  assert.deepEqual(sanitizeGPUInfo(null).fields, {});
  assert.deepEqual(sanitizeGPUInfo(undefined).fields, {});
  assert.equal(sanitizeGPUInfo('x').kept, 0);
});

test('sanitizeGPUInfo 不沿原型链取值', () => {
  const aux = Object.create({ glRenderer: 'proto' });
  aux.softwareRendering = true;
  const r = sanitizeGPUInfo(aux);
  assert.equal(r.fields.softwareRendering, true);
  assert.ok(!('glRenderer' in r.fields));
});

test('crashKey 区分 killed 与 reason', () => {
  assert.equal(crashKey({ killed: true }), 'killed:');
  assert.equal(crashKey({ killed: false }), 'crashed:');
  assert.equal(crashKey({ reason: 'oom' }), 'crashed:oom');
  assert.equal(crashKey(null), 'crashed:');
});

test('decideGPUCrash 首次记录，窗内同因抑制，过窗恢复', () => {
  const st = createCrashState();
  const input = { killed: false, reason: 'oom' };
  const r1 = decideGPUCrash(st, input, 0, DEFAULT_GPU_CRASH_COOLDOWN_MS);
  assert.equal(r1.action, ACTION_RECORD);
  assert.match(r1.detail, /崩溃/);
  const r2 = decideGPUCrash(st, input, 1000, DEFAULT_GPU_CRASH_COOLDOWN_MS);
  assert.equal(r2.action, ACTION_SUPPRESS);
  assert.equal(r2.suppressed, 1);
  const r3 = decideGPUCrash(st, input, DEFAULT_GPU_CRASH_COOLDOWN_MS + 1, DEFAULT_GPU_CRASH_COOLDOWN_MS);
  assert.equal(r3.action, ACTION_RECORD);
});

test('decideGPUCrash 不同原因不互相抑制', () => {
  const st = createCrashState();
  const a = decideGPUCrash(st, { reason: 'oom' }, 0);
  const b = decideGPUCrash(st, { reason: 'gpu-access-denied' }, 10);
  assert.equal(a.action, ACTION_RECORD);
  assert.equal(b.action, ACTION_RECORD);
});

test('decideGPUCrash killed 与 crashed 分别计数', () => {
  const st = createCrashState();
  const a = decideGPUCrash(st, { killed: true }, 0);
  const b = decideGPUCrash(st, { killed: false }, 5);
  assert.equal(a.killed, true);
  assert.equal(b.killed, false);
  assert.equal(a.action, ACTION_RECORD);
  assert.equal(b.action, ACTION_RECORD);
});

test('decideGPUCrash now<0 哨兵不节流', () => {
  const st = createCrashState();
  const input = { reason: 'oom' };
  assert.equal(decideGPUCrash(st, input, -1).action, ACTION_RECORD);
  assert.equal(decideGPUCrash(st, input, -1).action, ACTION_RECORD);
  assert.equal(st.suppressed, 0);
});

test('decideGPUCrash 缺入参不抛异常', () => {
  const r = decideGPUCrash(null, null, -1);
  assert.equal(r.action, ACTION_RECORD);
  assert.equal(r.killed, false);
});

test('decideAccessibilityChange 布尔归一', () => {
  const on = decideAccessibilityChange(true);
  assert.equal(on.known, true);
  assert.equal(on.enabled, true);
  assert.equal(on.shouldRecord, true);
  assert.match(on.detail, /打开/);
  const off = decideAccessibilityChange(false);
  assert.equal(off.shouldRecord, false);
  const unknown = decideAccessibilityChange('yes');
  assert.equal(unknown.known, false);
  assert.equal(unknown.shouldRecord, false);
});
