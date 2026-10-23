'use strict';

// localdeviceguard.test.js —— USB/HID/Serial/Bluetooth 设备门、acceptAll、敏感类/服务、
// 厂商白名单、句柄时长与串口波特率。

const test = require('node:test');
const assert = require('node:assert/strict');
const ld = require('./localdeviceguard');
const {
  LocalDeviceGuard, LD_REASON, API, defaultLocalDevicePolicy,
  normalizeBtUuid, usbAcceptAll, hasSensitiveUsbClass, hasSensitiveHidUsage, hasSensitiveBtService,
} = ld;

const ORIGIN = 'https://tools.example.com';
function ctx(over) {
  return Object.assign({
    origin: ORIGIN, isSecureContext: true, hasUserGesture: true, hasFocus: true,
    isBackground: false, blocked: false, now: 0,
  }, over || {});
}

test('蓝牙 UUID 归一化', () => {
  assert.equal(normalizeBtUuid('0x180F'), '0000180f');
  assert.equal(normalizeBtUuid('180f'), '0000180f');
  assert.equal(normalizeBtUuid('0000180f-0000-1000-8000-00805f9b34fb'), '0000180f');
  assert.equal(normalizeBtUuid('battery_service'), '');
});

test('USB acceptAll 识别', () => {
  assert.ok(usbAcceptAll({ acceptAllDevices: true }));
  assert.ok(usbAcceptAll({}));
  assert.ok(!usbAcceptAll({ filters: [{ vendorId: 1 }] }));
});

test('敏感 USB 类检测', () => {
  assert.equal(hasSensitiveUsbClass([{ classCode: 3 }]), 3);
  assert.equal(hasSensitiveUsbClass([{ classCode: 8 }]), 8);
  assert.equal(hasSensitiveUsbClass([{ classCode: 9 }]), -1);
});

test('敏感 HID usage page 检测', () => {
  assert.equal(hasSensitiveHidUsage([{ usagePage: 1 }]), 1);
  assert.equal(hasSensitiveHidUsage([{ usagePage: 7 }]), 7);
  assert.equal(hasSensitiveHidUsage([{ usagePage: 12 }]), -1);
});

test('敏感蓝牙服务检测', () => {
  assert.equal(hasSensitiveBtService(['0x180F', 'unknown']), '0000180f');
  assert.equal(hasSensitiveBtService(['180a']), '0000180a');
});

test('无手势/失焦/后台拒绝弹设备选择器', () => {
  const g = new LocalDeviceGuard();
  assert.equal(g.decideRequest(API.USB, ctx({ hasUserGesture: false }), { filters: [{ vendorId: 0x2341 }] }).reason, LD_REASON.NO_GESTURE);
  assert.equal(g.decideRequest(API.USB, ctx({ hasFocus: false }), { filters: [{ vendorId: 0x2341 }] }).reason, LD_REASON.NOT_FOCUSED);
  assert.equal(g.decideRequest(API.USB, ctx({ isBackground: true }), { filters: [{ vendorId: 0x2341 }] }).reason, LD_REASON.BACKGROUND);
});

test('USB acceptAll 默认拒绝', () => {
  const g = new LocalDeviceGuard();
  assert.equal(g.decideRequest(API.USB, ctx({ now: 0 }), { acceptAllDevices: true }).reason, LD_REASON.ACCEPT_ALL_FORBIDDEN);
});

test('USB 键盘/大容量类拒绝', () => {
  const g = new LocalDeviceGuard();
  assert.equal(g.decideRequest(API.USB, ctx({ now: 0 }), { filters: [{ classCode: 3 }] }).reason, LD_REASON.SENSITIVE_USB_CLASS);
  assert.equal(g.decideRequest(API.USB, ctx({ now: 2100 }), { filters: [{ classCode: 8 }] }).reason, LD_REASON.SENSITIVE_USB_CLASS);
});

test('厂商白名单', () => {
  const pol = defaultLocalDevicePolicy();
  pol.allowedVendorIds = [0x2341];
  const g = new LocalDeviceGuard(pol);
  assert.equal(g.decideRequest(API.USB, ctx({ now: 0 }), { filters: [{ vendorId: 0x2341 }] }).decision, 'prompt');
  assert.equal(g.decideRequest(API.USB, ctx({ now: 2100 }), { filters: [{ vendorId: 0x0483 }] }).reason, LD_REASON.VENDOR_NOT_ALLOWED);
});

test('HID 空过滤拒绝，键盘 usage page 拒绝', () => {
  const g = new LocalDeviceGuard();
  assert.equal(g.decideRequest(API.HID, ctx({ now: 0 }), { filters: [] }).reason, LD_REASON.EMPTY_FILTERS);
  assert.equal(g.decideRequest(API.HID, ctx({ now: 2100 }), { filters: [{ usagePage: 1 }] }).reason, LD_REASON.SENSITIVE_HID_USAGE);
});

test('蓝牙敏感服务拒绝，普通服务放行', () => {
  const g = new LocalDeviceGuard();
  assert.equal(g.decideRequest(API.BLUETOOTH, ctx({ now: 0 }), { acceptAllDevices: false, optionalServices: ['0x180F'] }).reason, LD_REASON.SENSITIVE_BT_SERVICE);
  assert.equal(g.decideRequest(API.BLUETOOTH, ctx({ now: 2100 }), { filters: [{ services: ['0x180D'] }] }).decision, 'prompt');
});

test('选择器节流', () => {
  const g = new LocalDeviceGuard();
  assert.equal(g.decideRequest(API.USB, ctx({ now: 0 }), { filters: [{ vendorId: 1, classCode: 9 }] }).decision, 'prompt');
  assert.equal(g.decideRequest(API.USB, ctx({ now: 500 }), { filters: [{ vendorId: 1, classCode: 9 }] }).reason, LD_REASON.PICKER_THROTTLED);
});

test('句柄数上限与会话超时', () => {
  const g = new LocalDeviceGuard();
  for (let i = 0; i < 6; i++) g.noteHandleOpened(ORIGIN, i);
  assert.equal(g.decideRequest(API.USB, ctx({ now: 999999 }), { filters: [{ vendorId: 1, classCode: 9 }] }).reason, LD_REASON.TOO_MANY_HANDLES);
  assert.equal(g.checkSession(ORIGIN, 31 * 60000).mustClose, true);
  assert.equal(g.checkSession(ORIGIN, 31 * 60000).reason, LD_REASON.HANDLE_SESSION_TOO_LONG);
  for (let i = 0; i < 6; i++) g.noteHandleClosed(ORIGIN);
  assert.equal(g.checkSession(ORIGIN, 31 * 60000).active, false);
});

test('串口波特率白名单', () => {
  const g = new LocalDeviceGuard();
  assert.equal(g.decideSerialOptions({ baudRate: 115200 }).allowed, true);
  assert.equal(g.decideSerialOptions({ baudRate: 12345 }).reason, LD_REASON.BAD_BAUD_RATE);
});
