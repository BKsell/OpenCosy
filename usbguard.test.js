'use strict';

// usbguard.test.js —— WebUSB：空 filter、ID/类范围、高风险类、厂商白名单、序列号指纹、claimInterface。

const test = require('node:test');
const assert = require('node:assert/strict');
const u = require('./usbguard');
const { UsbGuard, USB_REASON, defaultUsbPolicy, isUint16, isUint8, filterHasConstraint } = u;

function ctx(over) {
  return Object.assign({ origin: 'https://app.example.com', isTopFrame: true, userGesture: true }, over || {});
}

test('精确厂商/产品过滤放行', () => {
  const g = new UsbGuard();
  const r = g.decideRequest(ctx(), { filters: [{ vendorId: 0x2341, productId: 0x0043 }] });
  assert.equal(r.decision, 'allow');
});

test('空过滤器匹配全部设备被拒', () => {
  const g = new UsbGuard();
  assert.equal(g.decideRequest(ctx(), { filters: [{}] }).reason, USB_REASON.EMPTY_FILTER_MATCHES_ALL);
});

test('无 filters 被拒', () => {
  const g = new UsbGuard();
  assert.equal(g.decideRequest(ctx(), {}).reason, USB_REASON.NO_FILTER);
});

test('vendorId 越界被拒', () => {
  const g = new UsbGuard();
  assert.equal(g.decideRequest(ctx(), { filters: [{ vendorId: 0x10000 }] }).reason, USB_REASON.BAD_ID_RANGE);
  assert.equal(g.decideRequest(ctx(), { filters: [{ vendorId: -1 }] }).reason, USB_REASON.BAD_ID_RANGE);
  assert.equal(g.decideRequest(ctx(), { filters: [{ vendorId: 1.5 }] }).reason, USB_REASON.BAD_ID_RANGE);
});

test('classCode 越界被拒', () => {
  const g = new UsbGuard();
  assert.equal(g.decideRequest(ctx(), { filters: [{ classCode: 256 }] }).reason, USB_REASON.BAD_CLASS_RANGE);
});

test('大容量存储类被拒', () => {
  const g = new UsbGuard();
  assert.equal(g.decideRequest(ctx(), { filters: [{ vendorId: 1, classCode: 0x08 }] }).reason, USB_REASON.CLASS_BLOCKED);
});

test('智能卡类被拒', () => {
  const g = new UsbGuard();
  assert.equal(g.decideRequest(ctx(), { filters: [{ classCode: 0x0b }] }).reason, USB_REASON.CLASS_BLOCKED);
});

test('厂商自定义类被拒', () => {
  const g = new UsbGuard();
  assert.equal(g.decideRequest(ctx(), { filters: [{ classCode: 0xff }] }).reason, USB_REASON.CLASS_BLOCKED);
});

test('厂商白名单外被拒', () => {
  const pol = defaultUsbPolicy();
  pol.allowedVendorIds = [0x2341];
  const g = new UsbGuard(pol);
  assert.equal(g.decideRequest(ctx(), { filters: [{ vendorId: 0x0483 }] }).reason, USB_REASON.VENDOR_NOT_ALLOWED);
  assert.equal(g.decideRequest(ctx(), { filters: [{ vendorId: 0x2341 }] }).decision, 'allow');
});

test('序列号精确过滤默认拒绝', () => {
  const g = new UsbGuard();
  const r = g.decideRequest(ctx(), { filters: [{ vendorId: 1, serialNumber: 'SN-ABCDEF' }] });
  assert.equal(r.reason, USB_REASON.SERIAL_FINGERPRINT);
});

test('过滤器过多拒绝', () => {
  const g = new UsbGuard();
  const filters = [];
  for (let i = 0; i < 9; i++) filters.push({ vendorId: i + 1 });
  assert.equal(g.decideRequest(ctx(), { filters }).reason, USB_REASON.TOO_MANY_FILTERS);
});

test('无手势/跨源子框架/非 https 拒绝', () => {
  const g = new UsbGuard();
  const f = { filters: [{ vendorId: 1 }] };
  assert.equal(g.decideRequest(ctx({ userGesture: false }), f).reason, USB_REASON.NO_GESTURE);
  assert.equal(g.decideRequest(ctx({ isTopFrame: false }), f).reason, USB_REASON.CROSS_ORIGIN_SUBFRAME);
  assert.equal(g.decideRequest(ctx({ origin: 'http://x.test' }), f).reason, USB_REASON.INSECURE_ORIGIN);
});

test('claimInterface 对高风险接口类拦截', () => {
  const g = new UsbGuard();
  assert.equal(g.claimInterface(0x08).reason, USB_REASON.CLASS_BLOCKED);
  assert.equal(g.claimInterface(0x03).decision, 'allow');
  assert.equal(g.claimInterface(999).reason, USB_REASON.BAD_CLASS_RANGE);
});

test('范围与约束判定辅助函数', () => {
  assert.equal(isUint16(0xffff), true);
  assert.equal(isUint16(0x10000), false);
  assert.equal(isUint8(255), true);
  assert.equal(isUint8(256), false);
  assert.equal(filterHasConstraint({}), false);
  assert.equal(filterHasConstraint({ vendorId: 1 }), true);
  assert.equal(filterHasConstraint({ serialNumber: 'x' }), true);
});
