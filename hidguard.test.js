'use strict';

// hidguard.test.js —— WebHID：空 filter、ID/usage 范围、键盘/FIDO usagePage 拦截、集合深度/数量。

const test = require('node:test');
const assert = require('node:assert/strict');
const h = require('./hidguard');
const { HidGuard, HID_REASON, defaultHidPolicy, usageBlocked, HID_PAGE_FIDO, HID_GD_KEYBOARD } = h;

function ctx(over) {
  return Object.assign({ origin: 'https://app.example.com', isTopFrame: true, userGesture: true }, over || {});
}

test('合规厂商+非敏感 usage 放行', () => {
  const g = new HidGuard();
  const r = g.decideRequest(ctx(), { filters: [{ vendorId: 0x2341, usagePage: 0x09, usage: 0x01 }] });
  assert.equal(r.decision, 'allow');
});

test('无过滤器拒绝', () => {
  const g = new HidGuard();
  assert.equal(g.decideRequest(ctx(), {}).reason, HID_REASON.NO_FILTER);
});

test('空 filter 拒绝', () => {
  const g = new HidGuard();
  assert.equal(g.decideRequest(ctx(), { filters: [{}] }).reason, HID_REASON.EMPTY_FILTER);
});

test('键盘 Keypad usagePage 整页拦截', () => {
  const g = new HidGuard();
  assert.equal(g.decideRequest(ctx(), { filters: [{ usagePage: 0x07 }] }).reason, HID_REASON.BLOCKED_USAGE_PAGE);
});

test('FIDO usagePage 拦截', () => {
  const g = new HidGuard();
  const r = g.decideRequest(ctx(), { filters: [{ usagePage: HID_PAGE_FIDO }] });
  assert.equal(r.reason, HID_REASON.BLOCKED_USAGE_PAGE);
});

test('Generic Desktop 键盘 usage 拦截，非键盘放行', () => {
  const g = new HidGuard();
  assert.equal(g.decideRequest(ctx(), { filters: [{ usagePage: 0x01, usage: HID_GD_KEYBOARD }] }).reason,
    HID_REASON.BLOCKED_USAGE_PAGE);
  // Joystick=0x04，非键盘/小键盘，放行。
  assert.equal(g.decideRequest(ctx(), { filters: [{ usagePage: 0x01, usage: 0x04 }] }).decision, 'allow');
});

test('嵌套 collections 中的键盘 usage 拦截', () => {
  const g = new HidGuard();
  const r = g.decideRequest(ctx(), {
    filters: [{ vendorId: 1, collections: [{ usagePage: 0x09, children: [{ usagePage: 0x07 }] }] }],
  });
  assert.equal(r.reason, HID_REASON.BLOCKED_USAGE_PAGE);
});

test('集合过深拒绝', () => {
  const g = new HidGuard();
  let node = { usagePage: 0x09 };
  for (let i = 0; i < 6; i++) node = { usagePage: 0x09, children: [node] };
  const r = g.decideRequest(ctx(), { filters: [{ vendorId: 1, collections: [node] }] });
  assert.equal(r.reason, HID_REASON.COLLECTION_TOO_DEEP);
});

test('集合数量过多拒绝', () => {
  const g = new HidGuard();
  const many = [];
  for (let i = 0; i < 40; i++) many.push({ usagePage: 0x09 });
  const r = g.decideRequest(ctx(), { filters: [{ vendorId: 1, collections: many }] });
  assert.equal(r.reason, HID_REASON.TOO_MANY_COLLECTIONS);
});

test('usagePage/usage 越界拒绝', () => {
  const g = new HidGuard();
  assert.equal(g.decideRequest(ctx(), { filters: [{ usagePage: 0x10000 }] }).reason, HID_REASON.BAD_USAGE_RANGE);
  assert.equal(g.decideRequest(ctx(), { filters: [{ vendorId: 1, usage: -2 }] }).reason, HID_REASON.BAD_USAGE_RANGE);
});

test('vendorId 越界与白名单', () => {
  const g = new HidGuard();
  assert.equal(g.decideRequest(ctx(), { filters: [{ vendorId: 70000 }] }).reason, HID_REASON.BAD_ID_RANGE);
  const pol = defaultHidPolicy();
  pol.allowedVendorIds = [0x2341];
  const g2 = new HidGuard(pol);
  assert.equal(g2.decideRequest(ctx(), { filters: [{ vendorId: 1 }] }).reason, HID_REASON.VENDOR_NOT_ALLOWED);
});

test('usageBlocked 纯函数：GD 键盘拦、GD 摇杆放行、FIDO 拦', () => {
  const pol = defaultHidPolicy();
  assert.equal(usageBlocked(0x01, HID_GD_KEYBOARD, pol), true);
  assert.equal(usageBlocked(0x01, 0x04, pol), false);
  assert.equal(usageBlocked(HID_PAGE_FIDO, 0x01, pol), true);
  assert.equal(usageBlocked(0x09, 0x01, pol), false);
});

test('上下文三件套', () => {
  const g = new HidGuard();
  const f = { filters: [{ vendorId: 1 }] };
  assert.equal(g.decideRequest(ctx({ userGesture: false }), f).reason, HID_REASON.NO_GESTURE);
  assert.equal(g.decideRequest(ctx({ isTopFrame: false }), f).reason, HID_REASON.CROSS_ORIGIN_SUBFRAME);
  assert.equal(g.decideRequest(ctx({ origin: 'http://x' }), f).reason, HID_REASON.INSECURE_ORIGIN);
});
