'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  KIND_SERIAL,
  KIND_HID,
  KIND_USB,
  DECISION_CANCEL,
  originFromUrl,
  extractDeviceList,
  summarizeDevice,
  decideDeviceChooser,
  describeKind,
} = require('./devicerguard');

test('originFromUrl', () => {
  assert.equal(originFromUrl('https://a.test/x'), 'https://a.test');
  assert.equal(originFromUrl('bad'), '');
  assert.equal(originFromUrl(undefined), '');
});

test('extractDeviceList 兼容三种事件形态', () => {
  const serialPorts = [{ portName: 'COM3' }, { portName: 'COM4' }];
  assert.equal(extractDeviceList(KIND_SERIAL, null, serialPorts).length, 2);
  assert.equal(extractDeviceList(KIND_SERIAL, { portList: serialPorts }, null).length, 2);
  assert.equal(extractDeviceList(KIND_HID, { deviceList: [{ vendorId: 1 }] }).length, 1);
  assert.equal(extractDeviceList(KIND_USB, { devices: [{ vendorId: 2 }] }).length, 1);
  assert.deepEqual(extractDeviceList(KIND_HID, {}, null), []);
  assert.deepEqual(extractDeviceList(KIND_USB, null, null), []);
});

test('summarizeDevice 只统计标识存在性', () => {
  assert.deepEqual(summarizeDevice(KIND_SERIAL, { usbVendorId: 0x2341, usbProductId: 0x0043 }),
    { hasVendor: true, hasProduct: true });
  assert.deepEqual(summarizeDevice(KIND_SERIAL, { portName: 'COM1' }),
    { hasVendor: false, hasProduct: false });
  assert.deepEqual(summarizeDevice(KIND_HID, { vendorId: 1, productId: 2 }),
    { hasVendor: true, hasProduct: true });
  assert.deepEqual(summarizeDevice(KIND_USB, { vendorId: null, productId: 2 }),
    { hasVendor: false, hasProduct: true });
});

test('串口选择恒取消并计数', () => {
  const r = decideDeviceChooser({
    kind: KIND_SERIAL,
    originUrl: 'https://evil.test/',
    portList: [{ portName: 'COM3', usbVendorId: 1 }, { portName: 'COM4' }],
  });
  assert.equal(r.decision, DECISION_CANCEL);
  assert.equal(r.kind, 'serial');
  assert.equal(r.reason, 'serial-auto-select');
  assert.equal(r.origin, 'https://evil.test');
  assert.equal(r.deviceCount, 2);
  assert.equal(r.identified, 1);
});

test('HID 选择恒取消', () => {
  const r = decideDeviceChooser({
    kind: KIND_HID,
    originUrl: 'https://evil.test/',
    details: { deviceList: [{ vendorId: 0x04d9 }, { vendorId: 0x1234, productId: 0x5678 }] },
  });
  assert.equal(r.decision, DECISION_CANCEL);
  assert.equal(r.deviceCount, 2);
  assert.equal(r.identified, 2);
});

test('USB 选择恒取消，空列表也安全', () => {
  const r = decideDeviceChooser({ kind: KIND_USB, originUrl: 'bad url', details: {} });
  assert.equal(r.decision, DECISION_CANCEL);
  assert.equal(r.deviceCount, 0);
  assert.equal(r.identified, 0);
  assert.equal(r.origin, '');
});

test('未知 kind 被归一，不抛异常', () => {
  const r = decideDeviceChooser({ kind: 'printer', originUrl: 'https://a.test' });
  assert.equal(r.kind, 'unknown');
  assert.equal(r.decision, DECISION_CANCEL);
});

test('decideDeviceChooser 缺入参不抛异常', () => {
  const r = decideDeviceChooser(null);
  assert.equal(r.decision, DECISION_CANCEL);
  assert.equal(r.deviceCount, 0);
});

test('describeKind 中文类别', () => {
  assert.equal(describeKind(KIND_SERIAL), '串口');
  assert.equal(describeKind(KIND_HID), 'HID');
  assert.equal(describeKind(KIND_USB), 'USB');
  assert.equal(describeKind('x'), '未知设备');
});
