'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  KIND_HID,
  KIND_SERIAL,
  KIND_BLUETOOTH,
  ACTION_RECORD,
  ACTION_SUPPRESS,
  DEFAULT_REVOKE_COOLDOWN_MS,
  originFromUrl,
  describeKind,
  normalizeKind,
  clampString,
  summarizeDevice,
  deviceKey,
  dedupeKey,
  createRevokeState,
  decideRevocation,
} = require('./revokeguard');

test('normalizeKind / describeKind', () => {
  assert.equal(normalizeKind('hid'), KIND_HID);
  assert.equal(normalizeKind('serial'), KIND_SERIAL);
  assert.equal(normalizeKind('bluetooth'), KIND_BLUETOOTH);
  assert.equal(normalizeKind('printer'), '');
  assert.equal(normalizeKind(undefined), '');
  assert.equal(describeKind(KIND_HID), 'HID');
  assert.equal(describeKind(KIND_SERIAL), '串口');
  assert.equal(describeKind(KIND_BLUETOOTH), '蓝牙');
  assert.equal(describeKind('x'), '未知设备');
});

test('originFromUrl 安全取源', () => {
  assert.equal(originFromUrl('https://a.test/p'), 'https://a.test');
  assert.equal(originFromUrl('not a url'), '');
  assert.equal(originFromUrl(null), '');
});

test('clampString 去折行并截断', () => {
  assert.equal(clampString('a\nb', 10), 'a b');
  assert.equal(clampString('abcdef', 4), 'abcd…');
  assert.equal(clampString(null, 10), '');
});

test('summarizeDevice 识别硬件身份', () => {
  assert.deepEqual(summarizeDevice(KIND_HID, { vendorId: 1, productId: 2 }),
    { identifiable: true, vendorId: 1, productId: 2 });
  assert.deepEqual(summarizeDevice(KIND_SERIAL, { portName: 'COM3' }),
    { identifiable: true, vendorId: null, productId: null });
  assert.deepEqual(summarizeDevice(KIND_SERIAL, { usbVendorId: 0x23, usbProductId: 0x4 }),
    { identifiable: true, vendorId: 0x23, productId: 0x4 });
  const bt = summarizeDevice(KIND_BLUETOOTH, { deviceId: 'xx' });
  assert.equal(bt.identifiable, true);
  assert.equal(summarizeDevice(KIND_BLUETOOTH, {}).identifiable, false);
  assert.equal(summarizeDevice(KIND_HID, null).identifiable, false);
});

test('deviceKey 稳定且区分设备', () => {
  assert.equal(deviceKey(KIND_HID, { vendorId: 1, productId: 2 }), 'hid:1:2');
  assert.equal(deviceKey(KIND_SERIAL, { portName: 'COM3' }), 'serial:port:COM3');
  assert.equal(deviceKey(KIND_BLUETOOTH, { deviceId: 'abcdef' }), 'bt:6:abcdef');
  assert.equal(deviceKey(KIND_HID, {}), 'hid:unknown');
  // 同设备不同展示名 -> 同键
  assert.equal(
    deviceKey(KIND_HID, { vendorId: 1, productId: 2, productName: 'A' }),
    deviceKey(KIND_HID, { vendorId: 1, productId: 2, productName: 'B' }),
  );
});

test('dedupeKey 含源，跨源不合并', () => {
  const dev = { vendorId: 1, productId: 2 };
  const k1 = dedupeKey(KIND_HID, 'https://a.test', dev);
  const k2 = dedupeKey(KIND_HID, 'https://b.test', dev);
  assert.notEqual(k1, k2);
  assert.ok(k1.startsWith('https://a.test|'));
});

test('首次撤销记录，冷却窗内同键抑制（now>=0）', () => {
  const st = createRevokeState();
  const input = { kind: KIND_HID, originUrl: 'https://a.test', device: { vendorId: 1, productId: 2 } };
  const r1 = decideRevocation(st, input, 1000, DEFAULT_REVOKE_COOLDOWN_MS);
  assert.equal(r1.action, ACTION_RECORD);
  assert.match(r1.detail, /HID/);
  const r2 = decideRevocation(st, input, 1000 + 5000, DEFAULT_REVOKE_COOLDOWN_MS);
  assert.equal(r2.action, ACTION_SUPPRESS);
  assert.equal(r2.suppressed, 1);
  // 过了冷却窗重新记录
  const r3 = decideRevocation(st, input, 1000 + DEFAULT_REVOKE_COOLDOWN_MS + 1, DEFAULT_REVOKE_COOLDOWN_MS);
  assert.equal(r3.action, ACTION_RECORD);
});

test('now<0 哨兵：不节流，逐条记录（基准时间确定性）', () => {
  const st = createRevokeState();
  const input = { kind: KIND_SERIAL, originUrl: 'https://a.test', device: { portName: 'COM3' } };
  const r1 = decideRevocation(st, input, -1);
  const r2 = decideRevocation(st, input, -1);
  assert.equal(r1.action, ACTION_RECORD);
  assert.equal(r2.action, ACTION_RECORD);
  assert.equal(r2.suppressed, 0);
});

test('不同设备 / 不同类别互不抑制', () => {
  const st = createRevokeState();
  const a = decideRevocation(st, { kind: KIND_HID, originUrl: 'https://a.test', device: { vendorId: 1, productId: 1 } }, 0);
  const b = decideRevocation(st, { kind: KIND_HID, originUrl: 'https://a.test', device: { vendorId: 2, productId: 2 } }, 100);
  const c = decideRevocation(st, { kind: KIND_BLUETOOTH, originUrl: 'https://a.test', device: { deviceId: 'z' } }, 200);
  assert.equal(a.action, ACTION_RECORD);
  assert.equal(b.action, ACTION_RECORD);
  assert.equal(c.action, ACTION_RECORD);
});

test('蓝牙撤销按 deviceId 去重', () => {
  const st = createRevokeState();
  const input = { kind: KIND_BLUETOOTH, originUrl: 'https://a.test', device: { deviceId: 'dev-1' } };
  assert.equal(decideRevocation(st, input, 0).action, ACTION_RECORD);
  assert.equal(decideRevocation(st, input, 100).action, ACTION_SUPPRESS);
});

test('未知类别归一且不抛异常，仍节流', () => {
  const st = createRevokeState();
  const r1 = decideRevocation(st, { kind: 'weird', originUrl: 'https://a.test' }, 0);
  const r2 = decideRevocation(st, { kind: 'weird', originUrl: 'https://a.test' }, 100);
  assert.equal(r1.action, ACTION_RECORD);
  assert.equal(r1.kind, '');
  assert.equal(r2.action, ACTION_SUPPRESS);
});

test('缺入参不抛异常', () => {
  const r = decideRevocation(null, null, -1);
  assert.equal(r.action, ACTION_RECORD);
  assert.equal(createRevokeState().suppressed, 0);
});

test('total 统计所有事件', () => {
  const st = createRevokeState();
  decideRevocation(st, { kind: KIND_HID, originUrl: 'https://a.test', device: { vendorId: 1, productId: 1 } }, 0);
  decideRevocation(st, { kind: KIND_HID, originUrl: 'https://a.test', device: { vendorId: 1, productId: 1 } }, 10);
  assert.equal(st.total, 2);
});
