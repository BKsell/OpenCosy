'use strict';

// serialguard.test.js —— Web Serial：过滤、蓝牙信道、波特率、数据/停止位、parity、bufferSize。

const test = require('node:test');
const assert = require('node:assert/strict');
const s = require('./serialguard');
const { SerialGuard, SER_REASON, defaultSerialPolicy } = s;

function ctx(over) {
  return Object.assign({ origin: 'https://app.example.com', isTopFrame: true, userGesture: true }, over || {});
}

test('精确 USB vendor 过滤放行', () => {
  const g = new SerialGuard();
  assert.equal(g.decideRequest(ctx(), { filters: [{ usbVendorId: 0x2341 }] }).decision, 'allow');
});

test('无过滤器拒绝', () => {
  const g = new SerialGuard();
  assert.equal(g.decideRequest(ctx(), {}).reason, SER_REASON.NO_FILTER);
});

test('空 filter 对象拒绝', () => {
  const g = new SerialGuard();
  assert.equal(g.decideRequest(ctx(), { filters: [{}] }).reason, SER_REASON.EMPTY_FILTER);
});

test('allowAllDevices 拒绝', () => {
  const g = new SerialGuard();
  assert.equal(g.decideRequest(ctx(), { allowAllDevices: true }).reason, SER_REASON.NO_FILTER);
});

test('蓝牙通信用口默认拒绝', () => {
  const g = new SerialGuard();
  const r = g.decideRequest(ctx(), { allowedBluetoothServiceClassIds: ['00001101-0000-1000-8000-00805f9b34fb'] });
  assert.equal(r.reason, SER_REASON.BLUETOOTH_CHANNEL);
});

test('vendorId 越界拒绝', () => {
  const g = new SerialGuard();
  assert.equal(g.decideRequest(ctx(), { filters: [{ usbVendorId: 0x10000 }] }).reason, SER_REASON.BAD_VENDOR_RANGE);
});

test('厂商白名单外拒绝', () => {
  const pol = defaultSerialPolicy();
  pol.allowedVendorIds = [0x2341];
  const g = new SerialGuard(pol);
  assert.equal(g.decideRequest(ctx(), { filters: [{ usbVendorId: 0x0483 }] }).reason, SER_REASON.VENDOR_NOT_ALLOWED);
});

test('常规 115200 打开参数放行', () => {
  const g = new SerialGuard();
  const r = g.decideOpen({ baudRate: 115200, dataBits: 8, stopBits: 1, parity: 'none', bufferSize: 8192 });
  assert.equal(r.decision, 'allow');
});

test('非法波特率拒绝', () => {
  const g = new SerialGuard();
  assert.equal(g.decideOpen({ baudRate: 0 }).reason, SER_REASON.BAD_BAUD);
  assert.equal(g.decideOpen({ baudRate: -9600 }).reason, SER_REASON.BAD_BAUD);
  assert.equal(g.decideOpen({ baudRate: 12.5 }).reason, SER_REASON.BAD_BAUD);
});

test('超上限波特率拒绝', () => {
  const g = new SerialGuard();
  assert.equal(g.decideOpen({ baudRate: 9000000 }).reason, SER_REASON.BAD_BAUD);
});

test('非常规波特率默认拒绝但可放开', () => {
  const g = new SerialGuard();
  assert.equal(g.decideOpen({ baudRate: 12345 }).reason, SER_REASON.BAUD_UNUSUAL);
  const pol = defaultSerialPolicy();
  pol.allowUnusualBaud = true;
  const g2 = new SerialGuard(pol);
  assert.equal(g2.decideOpen({ baudRate: 12345 }).decision, 'allow');
});

test('dataBits/stopBits/parity/flowControl 非法值拒绝', () => {
  const g = new SerialGuard();
  assert.equal(g.decideOpen({ baudRate: 9600, dataBits: 5 }).reason, SER_REASON.BAD_DATA_BITS);
  assert.equal(g.decideOpen({ baudRate: 9600, stopBits: 1.5 }).reason, SER_REASON.BAD_STOP_BITS);
  assert.equal(g.decideOpen({ baudRate: 9600, parity: 'mark' }).reason, SER_REASON.BAD_PARITY);
  assert.equal(g.decideOpen({ baudRate: 9600, flowControl: 'weird' }).reason, SER_REASON.BAD_FLOW_CONTROL);
});

test('bufferSize 非法/过大拒绝', () => {
  const g = new SerialGuard();
  assert.equal(g.decideOpen({ baudRate: 9600, bufferSize: 0 }).reason, SER_REASON.BAD_BUFFER);
  assert.equal(g.decideOpen({ baudRate: 9600, bufferSize: 4 * 1024 * 1024 }).reason, SER_REASON.BUFFER_TOO_LARGE);
});

test('请求态手势/子框架/https 校验', () => {
  const g = new SerialGuard();
  const f = { filters: [{ usbVendorId: 1 }] };
  assert.equal(g.decideRequest(ctx({ userGesture: false }), f).reason, SER_REASON.NO_GESTURE);
  assert.equal(g.decideRequest(ctx({ isTopFrame: false }), f).reason, SER_REASON.CROSS_ORIGIN_SUBFRAME);
  assert.equal(g.decideRequest(ctx({ origin: 'http://a' }), f).reason, SER_REASON.INSECURE_ORIGIN);
});
