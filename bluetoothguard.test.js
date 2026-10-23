'use strict';

// bluetoothguard.test.js —— Web Bluetooth：手势/全设备/名称前缀/服务 UUID/optional 溢出与厂商扫描。

const test = require('node:test');
const assert = require('node:assert/strict');
const bt = require('./bluetoothguard');
const { BluetoothGuard, BT_REASON, canonicalServiceUuid, defaultBluetoothPolicy } = bt;

function ctx(over) {
  return Object.assign({ origin: 'https://app.example.com', isTopFrame: true, userGesture: true }, over || {});
}

test('合规单过滤器放行', () => {
  const g = new BluetoothGuard();
  const r = g.decideRequest(ctx(), { filters: [{ services: ['heart_rate'] }] });
  assert.equal(r.decision, 'allow');
});

test('非 https 拒绝', () => {
  const g = new BluetoothGuard();
  assert.equal(g.decideRequest(ctx({ origin: 'http://insecure.test' }), { filters: [{}] }).reason, BT_REASON.INSECURE_ORIGIN);
});

test('无手势拒绝', () => {
  const g = new BluetoothGuard();
  assert.equal(g.decideRequest(ctx({ userGesture: false }), { filters: [{}] }).reason, BT_REASON.NO_GESTURE);
});

test('跨源子框架默认拒绝', () => {
  const g = new BluetoothGuard();
  assert.equal(g.decideRequest(ctx({ isTopFrame: false }), { filters: [{}] }).reason, BT_REASON.CROSS_ORIGIN_SUBFRAME);
});

test('acceptAllDevices 默认拒绝', () => {
  const g = new BluetoothGuard();
  assert.equal(g.decideRequest(ctx(), { acceptAllDevices: true }).reason, BT_REASON.ACCEPT_ALL_DEVICES);
});

test('无过滤器拒绝', () => {
  const g = new BluetoothGuard();
  assert.equal(g.decideRequest(ctx(), { filters: [] }).reason, BT_REASON.NO_FILTER);
});

test('名称前缀过短拒绝', () => {
  const g = new BluetoothGuard();
  assert.equal(g.decideRequest(ctx(), { filters: [{ namePrefix: 'AB' }] }).reason, BT_REASON.NAME_PREFIX_TOO_SHORT);
});

test('名称前缀含控制字符拒绝', () => {
  const g = new BluetoothGuard();
  assert.equal(g.decideRequest(ctx(), { filters: [{ namePrefix: 'Good\nName' }] }).reason, BT_REASON.NAME_PREFIX_CONTROL_CHAR);
});

test('名称前缀超长拒绝', () => {
  const g = new BluetoothGuard();
  const longName = 'A'.repeat(30);
  assert.equal(g.decideRequest(ctx(), { filters: [{ namePrefix: longName }] }).reason, BT_REASON.NAME_PREFIX_TOO_LONG);
});

test('必需服务 UUID 白名单生效', () => {
  const pol = defaultBluetoothPolicy();
  pol.allowedServiceUuids = ['heart_rate'];
  const g = new BluetoothGuard(pol);
  assert.equal(g.decideRequest(ctx(), { filters: [{ services: ['battery_service'] }] }).reason,
    BT_REASON.SERVICE_UUID_NOT_ALLOWED);
});

test('optionalServices 128-bit 厂商私有服务拒绝', () => {
  const g = new BluetoothGuard();
  const r = g.decideRequest(ctx(), {
    filters: [{ services: ['heart_rate'] }],
    optionalServices: ['0000ffe0-0000-1000-8000-00805f9b34fb'],
  });
  assert.equal(r.reason, BT_REASON.OPTIONAL_SERVICE_TOO_BROAD);
});

test('optionalServices 敏感短名拒绝', () => {
  const g = new BluetoothGuard();
  const r = g.decideRequest(ctx(), { filters: [{}], optionalServices: ['device_information'] });
  assert.equal(r.reason, BT_REASON.OPTIONAL_SERVICE_TOO_BROAD);
});

test('optionalServices 超量拒绝', () => {
  const g = new BluetoothGuard();
  const r = g.decideRequest(ctx(), { filters: [{}], optionalServices: ['heart_rate', 'tx_power', 'link_loss'] });
  assert.equal(r.reason, BT_REASON.OPTIONAL_SERVICE_OVERFLOW);
});

test('manufacturerData 扫描默认拒绝', () => {
  const g = new BluetoothGuard();
  const r = g.decideRequest(ctx(), { filters: [{ manufacturerData: [{ companyIdentifier: 0x004c }] }] });
  assert.equal(r.reason, BT_REASON.MANUFACTURER_SCAN);
});

test('非法 UUID 拒绝', () => {
  const g = new BluetoothGuard();
  assert.equal(g.decideRequest(ctx(), { filters: [{ services: ['not-a-uuid'] }] }).reason, BT_REASON.BAD_UUID);
});

test('UUID 归一化：短名/裸十六进制/0x/128 位', () => {
  assert.equal(canonicalServiceUuid('heart_rate').token, '16:180d');
  assert.equal(canonicalServiceUuid('180D').token, '16:180d');
  assert.equal(canonicalServiceUuid('0x180D').token, '16:180d');
  assert.equal(canonicalServiceUuid(0x180d).bits, 16);
  assert.equal(canonicalServiceUuid('0000180d-0000-1000-8000-00805f9b34fb').bits, 128);
  assert.equal(canonicalServiceUuid('zzzz').ok, false);
  assert.equal(canonicalServiceUuid(-1).ok, false);
});
